/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.sufficientlysecure.privacybox;

import static org.sufficientlysecure.privacybox.VaultProvider.TAG;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.database.MatrixCursor;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.Messenger;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.provider.DocumentsContract.Document;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;
import org.openintents.openpgp.OpenPgpError;
import org.openintents.openpgp.OpenPgpMetadata;
import org.openintents.openpgp.util.OpenPgpApi;
import org.openintents.openpgp.util.OpenPgpServiceConnection;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.ProtocolException;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Represents a single encrypted document stored on disk. Handles encryption,
 * decryption, and authentication of the document when requested.
 * <p/>
 * Encrypted documents are stored on disk as a magic number, followed by an
 * encrypted metadata section, followed by an encrypted content section. The
 * content section always starts at a specific offset {@link #CONTENT_OFFSET} to
 * allow metadata updates without rewriting the entire file.
 * <p/>
 * Each section is encrypted using AES-128 with a random IV, and authenticated
 * with SHA-256. Data encrypted and authenticated like this can be safely stored
 * on untrusted storage devices, as long as the keys are stored securely.
 * <p/>
 * Not inherently thread safe.
 */
public class EncryptedDocument {

    /**
     * Magic number to identify file; "AVLT".
     */
    private static final int MAGIC_NUMBER = 0x41564c54;

    /**
     * Offset in file at which content section starts. Magic and metadata
     * section must fully fit before this offset.
     */
    private static final int CONTENT_OFFSET = 4096;

    private static final boolean DEBUG_METADATA = true;

    /**
     * Key length for AES-128
     */
    public static final int DATA_KEY_LENGTH = 16;
    /**
     * Key length for SHA-256
     */
    public static final int MAC_KEY_LENGTH = 32;

    private final SecureRandom mRandom;
    private final Cipher mCipher;
    private final Mac mMac;

    private final long mDocId;
    private final File mFile;
//    private final SecretKey mDataKey;
//    private final SecretKey mMacKey;

    OpenPgpServiceConnection mServiceConnection;
    Context mContext;

    /**
     * Create an encrypted document.
     *
     * @param docId     the expected {@link Document#COLUMN_DOCUMENT_ID} to be
     *                  validated when reading metadata.
     * @param directory location on disk where the encrypted document is stored. May
     *                  not exist yet.
     */
    public EncryptedDocument(long docId, File directory, Context context, OpenPgpServiceConnection serviceConnection)
            throws GeneralSecurityException {
        mRandom = new SecureRandom();
        mCipher = Cipher.getInstance("AES/CTR/NoPadding");
        mMac = Mac.getInstance("HmacSHA256");

        mServiceConnection = serviceConnection;
        mContext = context;


//        if (dataKey.getEncoded().length != DATA_KEY_LENGTH) {
//            throw new IllegalArgumentException("Expected data key length " + DATA_KEY_LENGTH);
//        }
//        if (macKey.getEncoded().length != MAC_KEY_LENGTH) {
//            throw new IllegalArgumentException("Expected MAC key length " + MAC_KEY_LENGTH);
//        }

        mDocId = docId;
        mFile = new File(directory, String.valueOf(docId) + ".gpg");
//        mDataKey = dataKey;
//        mMacKey = macKey;
    }

    public File getFile() {
        return mFile;
    }

    @Override
    public String toString() {
        return mFile.getName();
    }

    /**
     * Decrypt and return parsed metadata section from this document.
     *
     * @throws DigestException if metadata fails MAC check, or if
     *                         {@link Document#COLUMN_DOCUMENT_ID} recorded in metadata is
     *                         unexpected.
     */
    public JSONObject readMetadata() throws IOException, GeneralSecurityException {
        InputStream fis = new FileInputStream(mFile);

        try {
            Intent data = new Intent();
            data.setAction(OpenPgpApi.ACTION_DECRYPT_METADATA);
            data.putExtra(OpenPgpApi.EXTRA_ACCOUNT_NAME, "default");
            OpenPgpApi api = new OpenPgpApi(mContext, mServiceConnection.getService());
            Intent result = api.executeApi(data, fis, null);

            // TODO: better handling of errors
            OpenPgpMetadata openPgpMeta;
            if (result.hasExtra(OpenPgpApi.RESULT_METADATA)) {
                openPgpMeta = result.getParcelableExtra(OpenPgpApi.RESULT_METADATA);
            } else {
                throw new IOException();
            }

            Log.d(TAG, "metadata for " + mDocId + ": " + openPgpMeta);

            String mimeType = openPgpMeta.getMimeType();
            String filename = openPgpMeta.getFilename();
            long size = openPgpMeta.getOriginalSize();
            long modTime = openPgpMeta.getModificationTime();

            // HACK: dirs have a special encrypted filename
            if (Document.MIME_TYPE_DIR.equals(filename)) {
                mimeType = Document.MIME_TYPE_DIR;
            }

            final JSONObject meta = new JSONObject();
            meta.put(Document.COLUMN_DOCUMENT_ID, mDocId);
            meta.put(Document.COLUMN_DISPLAY_NAME, filename);
            meta.put(Document.COLUMN_MIME_TYPE, mimeType);
            meta.put(Document.COLUMN_SIZE, size);
            meta.put(Document.COLUMN_LAST_MODIFIED, modTime);

            return meta;
        } catch (JSONException e) {
            throw new IOException(e);
        } finally {
            fis.close();
        }
    }

    /**
     * Decrypt and read content section of this document, writing it into the
     * given pipe.
     * <p/>
     * Pipe is left open, so caller is responsible for calling
     * {@link ParcelFileDescriptor#close()} or
     * {@link ParcelFileDescriptor#closeWithError(String)}.
     *
     * @param contentOut write end of a pipe.
     * @throws DigestException if content fails MAC check. Some or all content
     *                         may have already been written to the pipe when the MAC is
     *                         validated.
     */
    public void readContent(ParcelFileDescriptor contentOut)
            throws IOException, GeneralSecurityException {
//        final RandomAccessFile f = new RandomAccessFile(mFile, "r");
//        try {
//            assertMagic(f);
//
//            if (f.length() <= CONTENT_OFFSET) {
//                throw new IOException("Document has no content");
//            }
//
//            // Skip over metadata section
//            f.seek(CONTENT_OFFSET);
//            readSection(f, new FileOutputStream(contentOut.getFileDescriptor()));
//
//        } finally {
//            f.close();
//        }
    }

    /**
     * Encrypt and write both the metadata and content sections of this
     * document, reading the content from the given pipe. Internally uses
     * {@link ParcelFileDescriptor#checkError()} to verify that content arrives
     * without errors. Writes to temporary file to keep atomic view of contents,
     * swapping into place only when write is successful.
     * <p/>
     * Pipe is left open, so caller is responsible for calling
     * {@link ParcelFileDescriptor#close()} or
     * {@link ParcelFileDescriptor#closeWithError(String)}.
     *
     * @param contentIn read end of a pipe.
     */
    public void writeMetadataAndContent(JSONObject meta, ParcelFileDescriptor contentIn)
            throws IOException, GeneralSecurityException {
        // Write into temporary file to provide an atomic view of existing
        // contents during write, and also to recover from failed writes.
        final String tempName = mFile.getName() + ".tmp_" + Thread.currentThread().getId();
        final File tempFile = new File(mFile.getParentFile(), tempName);

//        RandomAccessFile f = new RandomAccessFile(tempFile, "rw");
        try {


            // TODO: WHILE NOT RESULT_CODE_SUCCESS wait notify and stuff...
            Intent data = new Intent();
            data.setAction(OpenPgpApi.ACTION_SIGN_AND_ENCRYPT);
            data.putExtra(OpenPgpApi.EXTRA_ORIGINAL_FILENAME, meta.getString(Document.COLUMN_DISPLAY_NAME));
            data.putExtra(OpenPgpApi.EXTRA_USER_IDS, new String[]{"nopass@example.com"});
            data.putExtra(OpenPgpApi.EXTRA_ACCOUNT_NAME, "default");
            OpenPgpApi api = new OpenPgpApi(mContext, mServiceConnection.getService());

            InputStream is;
            if (contentIn == null) {
                // just a directory
                is = new ByteArrayInputStream("directory".getBytes());
            } else {
                is = new FileInputStream(contentIn.getFileDescriptor());
            }
            Intent result = api.executeApi(data, is, new FileOutputStream(tempFile));

            switch (result.getIntExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_ERROR)) {
                case OpenPgpApi.RESULT_CODE_SUCCESS: {
                    Log.d(VaultProvider.TAG, "writeMetadataAndContent RESULT_CODE_SUCCESS");

                    tempFile.renameTo(mFile);

                    break;
                }
                case OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED: {
                    Log.d(VaultProvider.TAG, "writeMetadataAndContent RESULT_CODE_USER_INTERACTION_REQUIRED");

                    // directly try again, something different needs user interaction again...
                    PendingIntent pi = result.getParcelableExtra(OpenPgpApi.RESULT_INTENT);

                    Handler handler = new Handler(mContext.getMainLooper(), new Handler.Callback() {
                        @Override
                        public boolean handleMessage(Message msg) {
                            Log.d(VaultProvider.TAG, "writeMetadataAndContent handleMessage");

                            // TODO: start again afterwards!!!
                            return true;
                        }
                    });
                    Messenger messenger = new Messenger(handler);

                    // start proxy activity and wait here for it finishing...
                    Intent proxy = new Intent(mContext, KeychainProxyActivity.class);
                    proxy.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    proxy.putExtra(KeychainProxyActivity.EXTRA_MESSENGER, messenger);
                    proxy.putExtra(KeychainProxyActivity.EXTRA_PENDING_INTENT, pi);

                    mContext.startActivity(proxy);
                    break;
                }
                case OpenPgpApi.RESULT_CODE_ERROR: {
                    Log.d(VaultProvider.TAG, "writeMetadataAndContent RESULT_CODE_ERROR");

                    // TODO
                    OpenPgpError error = result.getParcelableExtra(OpenPgpApi.RESULT_ERROR);
//                handleError(error);
                    break;
                }
            }

            // Truncate any existing data
//            f.setLength(0);

            // Write content first to detect size
//            if (contentIn != null) {
//                f.seek(CONTENT_OFFSET);
//                final int plainLength = writeSection(
//                        f, new FileInputStream(contentIn.getFileDescriptor()));
//                meta.put(Document.COLUMN_SIZE, plainLength);
//
//                // Verify that remote side of pipe finished okay; if they
//                // crashed or indicated an error then this throws and we
//                // leave the original file intact and clean up temp below.
//                contentIn.checkError();
//            }

//            meta.put(Document.COLUMN_DOCUMENT_ID, mDocId);
//            meta.put(Document.COLUMN_LAST_MODIFIED, System.currentTimeMillis());

            // Rewind and write metadata section
//            f.seek(0);
//            f.writeInt(MAGIC_NUMBER);

//            final ByteArrayInputStream metaIn = new ByteArrayInputStream(
//                    meta.toString().getBytes(StandardCharsets.UTF_8));
//            writeSection(f, metaIn);
//
//            if (f.getFilePointer() > CONTENT_OFFSET) {
//                throw new IOException("Metadata section was too large");
//            }

            // Everything written fine, atomically swap new data into place.
            // fsync() before close would be overkill, since rename() is an
            // atomic barrier.
//            f.close();

        } catch (JSONException e) {
            throw new IOException(e);
        } finally {
            // Regardless of what happens, always try cleaning up.
//            f.close();
            tempFile.delete();
        }
    }

    /**
     * Read and decrypt the section starting at the current file offset.
     * Validates MAC of decrypted data, throwing if mismatch. When finished,
     * file offset is at the end of the entire section.
     */
//    private void readSection(RandomAccessFile f, OutputStream out)
//            throws IOException, GeneralSecurityException {
//        final long start = f.getFilePointer();
//
//        final Section section = new Section();
//        section.read(f);
//
//        final IvParameterSpec ivSpec = new IvParameterSpec(section.iv);
//        mCipher.init(Cipher.DECRYPT_MODE, mDataKey, ivSpec);
//        mMac.init(mMacKey);
//
//        byte[] inbuf = new byte[8192];
//        byte[] outbuf;
//        int n;
//        while ((n = f.read(inbuf, 0, (int) Math.min(section.length, inbuf.length))) != -1) {
//            section.length -= n;
//            mMac.update(inbuf, 0, n);
//            outbuf = mCipher.update(inbuf, 0, n);
//            if (outbuf != null) {
//                out.write(outbuf);
//            }
//            if (section.length == 0) break;
//        }
//
//        section.assertMac(mMac.doFinal());
//
//        outbuf = mCipher.doFinal();
//        if (outbuf != null) {
//            out.write(outbuf);
//        }
//    }

    /**
     * Encrypt and write the given stream as a full section. Writes section
     * header and encrypted data starting at the current file offset. When
     * finished, file offset is at the end of the entire section.
     */
//    private int writeSection(RandomAccessFile f, InputStream in)
//            throws IOException, GeneralSecurityException {
//        final long start = f.getFilePointer();
//
//        // Write header; we'll come back later to finalize details
//        final Section section = new Section();
//        section.write(f);
//
//        final long dataStart = f.getFilePointer();
//
//        mRandom.nextBytes(section.iv);
//
//        final IvParameterSpec ivSpec = new IvParameterSpec(section.iv);
//        mCipher.init(Cipher.ENCRYPT_MODE, mDataKey, ivSpec);
//        mMac.init(mMacKey);
//
//        int plainLength = 0;
//        byte[] inbuf = new byte[8192];
//        byte[] outbuf;
//        int n;
//        while ((n = in.read(inbuf)) != -1) {
//            plainLength += n;
//            outbuf = mCipher.update(inbuf, 0, n);
//            if (outbuf != null) {
//                mMac.update(outbuf);
//                f.write(outbuf);
//            }
//        }
//
//        outbuf = mCipher.doFinal();
//        if (outbuf != null) {
//            mMac.update(outbuf);
//            f.write(outbuf);
//        }
//
//        section.setMac(mMac.doFinal());
//
//        final long dataEnd = f.getFilePointer();
//        section.length = dataEnd - dataStart;
//
//        // Rewind and update header
//        f.seek(start);
//        section.write(f);
//        f.seek(dataEnd);
//
//        return plainLength;
//    }

    /**
     * Header of a single file section.
     */
//    private static class Section {
//        long length;
//        final byte[] iv = new byte[DATA_KEY_LENGTH];
//        final byte[] mac = new byte[MAC_KEY_LENGTH];
//
//        public void read(RandomAccessFile f) throws IOException {
//            length = f.readLong();
//            f.readFully(iv);
//            f.readFully(mac);
//        }
//
//        public void write(RandomAccessFile f) throws IOException {
//            f.writeLong(length);
//            f.write(iv);
//            f.write(mac);
//        }
//
//        public void setMac(byte[] mac) {
//            if (mac.length != this.mac.length) {
//                throw new IllegalArgumentException("Unexpected MAC length");
//            }
//            System.arraycopy(mac, 0, this.mac, 0, this.mac.length);
//        }
//
//        public void assertMac(byte[] mac) throws DigestException {
//            if (mac.length != this.mac.length) {
//                throw new IllegalArgumentException("Unexpected MAC length");
//            }
//            byte result = 0;
//            for (int i = 0; i < mac.length; i++) {
//                result |= mac[i] ^ this.mac[i];
//            }
//            if (result != 0) {
//                throw new DigestException();
//            }
//        }
//    }

//    private static void assertMagic(RandomAccessFile f) throws IOException {
//        final int magic = f.readInt();
//        if (magic != MAGIC_NUMBER) {
//            throw new ProtocolException("Bad magic number: " + Integer.toHexString(magic));
//        }
//    }


//    private class MyCallback implements OpenPgpApi.IOpenPgpCallback {
//        boolean returnToCiphertextField;
//        ByteArrayOutputStream os;
//        int requestCode;
//
//        private MyCallback(boolean returnToCiphertextField, ByteArrayOutputStream os, int requestCode) {
//            this.returnToCiphertextField = returnToCiphertextField;
//            this.os = os;
//            this.requestCode = requestCode;
//        }
//
//        @Override
//        public void onReturn(Intent result) {
//            switch (result.getIntExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_ERROR)) {
//                case OpenPgpApi.RESULT_CODE_SUCCESS: {
//                    showToast("RESULT_CODE_SUCCESS");
//// encrypt/decrypt/sign/verify
//                    if (os != null) {
//                        try {
//                            Log.d(OpenPgpApi.TAG, "result: " + os.toByteArray().length
//                                    + " str=" + os.toString("UTF-8"));
//                            if (returnToCiphertextField) {
//                                mCiphertext.setText(os.toString("UTF-8"));
//                            } else {
//                                mMessage.setText(os.toString("UTF-8"));
//                            }
//                        } catch (UnsupportedEncodingException e) {
//                            Log.e(Constants.TAG, "UnsupportedEncodingException", e);
//                        }
//                    }
//// verify
//                    if (result.hasExtra(OpenPgpApi.RESULT_SIGNATURE)) {
//                        OpenPgpSignatureResult sigResult
//                                = result.getParcelableExtra(OpenPgpApi.RESULT_SIGNATURE);
//                        showToast(sigResult.toString());
//                    }
//// get key ids
//                    if (result.hasExtra(OpenPgpApi.RESULT_KEY_IDS)) {
//                        long[] keyIds = result.getLongArrayExtra(OpenPgpApi.RESULT_KEY_IDS);
//                        String out = "keyIds: ";
//                        for (int i = 0; i < keyIds.length; i++) {
//                            out += OpenPgpUtils.convertKeyIdToHex(keyIds[i]) + ", ";
//                        }
//                        showToast(out);
//                    }
//                    break;
//                }
//                case OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED: {
//                    showToast("RESULT_CODE_USER_INTERACTION_REQUIRED");
//                    PendingIntent pi = result.getParcelableExtra(OpenPgpApi.RESULT_INTENT);
//                    try {
//                        OpenPgpProviderActivity.this.startIntentSenderForResult(pi.getIntentSender(),
//                                requestCode, null, 0, 0, 0);
//                    } catch (IntentSender.SendIntentException e) {
//                        Log.e(Constants.TAG, "SendIntentException", e);
//                    }
//                    break;
//                }
//                case OpenPgpApi.RESULT_CODE_ERROR: {
//                    showToast("RESULT_CODE_ERROR");
//                    OpenPgpError error = result.getParcelableExtra(OpenPgpApi.RESULT_ERROR);
//                    handleError(error);
//                    break;
//                }
//            }
//        }
//    }

//    public void sign(Intent data, InputStream is) {
//        data.setAction(OpenPgpApi.ACTION_SIGN);
//        data.putExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, true);
//        data.putExtra(OpenPgpApi.EXTRA_ACCOUNT_NAME, "default");
//        ByteArrayOutputStream os = new ByteArrayOutputStream();
//        OpenPgpApi api = new OpenPgpApi(this, mServiceConnection.getService());
//        api.executeApiAsync(data, is, os, new MyCallback(true, os, REQUEST_CODE_SIGN));
//    }
//
//    public void encrypt(Intent data, InputStream is) {
//        data.setAction(OpenPgpApi.ACTION_ENCRYPT);
////        data.putExtra(OpenPgpApi.EXTRA_USER_IDS, mEncryptUserIds.getText().toString().split(","));
//        data.putExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, true);
//        data.putExtra(OpenPgpApi.EXTRA_ACCOUNT_NAME, "default");
//        ByteArrayOutputStream os = new ByteArrayOutputStream();
//        OpenPgpApi api = new OpenPgpApi(this, mServiceConnection.getService());
//        api.executeApiAsync(data, is, os, new MyCallback(true, os, REQUEST_CODE_ENCRYPT));
//    }
//
//    public void signAndEncrypt(Intent data, InputStream is) {
//        data.setAction(OpenPgpApi.ACTION_SIGN_AND_ENCRYPT);
//        data.putExtra(OpenPgpApi.EXTRA_USER_IDS, mEncryptUserIds.getText().toString().split(","));
//        data.putExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, true);
//        data.putExtra(OpenPgpApi.EXTRA_ACCOUNT_NAME, "default");
//        ByteArrayOutputStream os = new ByteArrayOutputStream();
//        OpenPgpApi api = new OpenPgpApi(this, mServiceConnection.getService());
//        api.executeApiAsync(data, is, os, new MyCallback(true, os, REQUEST_CODE_SIGN_AND_ENCRYPT));
//    }
//
//    public void decryptAndVerify(Intent data, InputStream is) {
//        data.setAction(OpenPgpApi.ACTION_DECRYPT_VERIFY);
//        data.putExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, true);
//        data.putExtra(OpenPgpApi.EXTRA_ACCOUNT_NAME, "default");
//        ByteArrayOutputStream os = new ByteArrayOutputStream();
//        OpenPgpApi api = new OpenPgpApi(this, mServiceConnection.getService());
//        api.executeApiAsync(data, is, os, new MyCallback(false, os, REQUEST_CODE_DECRYPT_AND_VERIFY));
//    }

//    public void getKey(Intent data) {
//        data.setAction(OpenPgpApi.ACTION_GET_KEY);
//        data.putExtra(OpenPgpApi.EXTRA_ACCOUNT_NAME, mAccount.getText().toString());
//        data.putExtra(OpenPgpApi.EXTRA_KEY_ID, Long.decode(mGetKeyEdit.getText().toString()));
//        OpenPgpApi api = new OpenPgpApi(this, mServiceConnection.getService());
//        api.executeApiAsync(data, null, null, new MyCallback(false, null, REQUEST_CODE_GET_KEY));
//    }
//
//    public void getKeyIds(Intent data) {
//        data.setAction(OpenPgpApi.ACTION_GET_KEY_IDS);
//        data.putExtra(OpenPgpApi.EXTRA_ACCOUNT_NAME, mAccount.getText().toString());
//        data.putExtra(OpenPgpApi.EXTRA_USER_IDS, mGetKeyIdsEdit.getText().toString().split(","));
//        OpenPgpApi api = new OpenPgpApi(this, mServiceConnection.getService());
//        api.executeApiAsync(data, null, null, new MyCallback(false, null, REQUEST_CODE_GET_KEY_IDS));
//    }
}
