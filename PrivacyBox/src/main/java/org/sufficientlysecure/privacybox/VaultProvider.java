/*
 * Copyright (C) 2014 Dominik Schürmann <dominik@dominikschuermann.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.sufficientlysecure.privacybox;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.database.MatrixCursor.RowBuilder;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.os.Messenger;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract;
import android.provider.DocumentsContract.Document;
import android.provider.DocumentsContract.Root;
import android.provider.DocumentsProvider;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.openintents.openpgp.IOpenPgpService;
import org.openintents.openpgp.util.OpenPgpServiceConnection;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;

import static org.sufficientlysecure.privacybox.Utils.closeQuietly;
import static org.sufficientlysecure.privacybox.Utils.closeWithErrorQuietly;

/**
 * Provider that encrypts both metadata and contents of documents stored inside.
 * Each document is stored as described by {@link EncryptedDocument} with
 * separate metadata and content sections. Directories are just
 * {@link EncryptedDocument} instances without a content section, and a list of
 * child documents included in the metadata section.
 * <p/>
 * All content is encrypted/decrypted on demand through pipes, using
 * {@link ParcelFileDescriptor#createReliablePipe()} to detect and recover from
 * remote crashes and errors.
 */
public class VaultProvider extends DocumentsProvider {
    public static final String TAG = "PrivacyBox";

    static final String AUTHORITY = "org.sufficientlysecure.privacybox.provider";

    static final String DEFAULT_ROOT_ID = "privacybox";
    static final String DEFAULT_DOCUMENT_ID = "0";

    /**
     * JSON key storing array of all children documents in a directory.
     */
    public static final String KEY_CHILDREN = "privacybox:children";

    /**
     * Key pointing to next available document ID.
     */
    private static final String PREF_NEXT_ID = "next_id";

    private static final String[] DEFAULT_ROOT_PROJECTION = new String[]{
            Root.COLUMN_ROOT_ID, Root.COLUMN_FLAGS, Root.COLUMN_ICON, Root.COLUMN_TITLE,
            Root.COLUMN_DOCUMENT_ID, Root.COLUMN_AVAILABLE_BYTES, Root.COLUMN_SUMMARY
    };

    private static final String[] DEFAULT_DOCUMENT_PROJECTION = new String[]{
            Document.COLUMN_DOCUMENT_ID, Document.COLUMN_MIME_TYPE, Document.COLUMN_DISPLAY_NAME,
            Document.COLUMN_LAST_MODIFIED, Document.COLUMN_FLAGS, Document.COLUMN_SIZE,
    };

    private static String[] resolveRootProjection(String[] projection) {
        return projection != null ? projection : DEFAULT_ROOT_PROJECTION;
    }

    private static String[] resolveDocumentProjection(String[] projection) {
        return projection != null ? projection : DEFAULT_DOCUMENT_PROJECTION;
    }

    private final Object mIdLock = new Object();

    private final Object mUILock = new Object();

    private OpenPgpServiceConnection mServiceConnection;

    private static final String OPEN_KEYCHAIN_PACKAGE = "org.sufficientlysecure.keychain";

    /**
     * Directory where all encrypted documents are stored.
     */
    private File mDocumentsDir;

    @Override
    public boolean onCreate() {
        Log.d(TAG, "VaultProvider.onCreate");

        mDocumentsDir = new File(getContext().getFilesDir(), "documents");
        mDocumentsDir.mkdirs();

        mServiceConnection = new OpenPgpServiceConnection(
                getContext(),
                OPEN_KEYCHAIN_PACKAGE,
                new OpenPgpServiceConnection.OnBound() {
                    @Override
                    public void onBound(IOpenPgpService service) {
                        Log.d(TAG, "onBound");

                        try {
                            // ensure that our root document is ready.
                            initDocument(Long.parseLong(DEFAULT_DOCUMENT_ID), Document.MIME_TYPE_DIR, "root");
                        } catch (IOException e) {
                            throw new IllegalStateException(e);
                        } catch (GeneralSecurityException e) {
                            throw new IllegalStateException(e);
                        }
                    }

                    @Override
                    public void onError(Exception e) {
                        Log.e(TAG, "exception when binding to service!", e);
                    }
                }
        );

        mServiceConnection.bindToService();

        // TODO
        // I was not able to do bindToService to the provider via a thread and wait/notify...
        // maybe binding does not work from every thread???
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return true;
    }

    /**
     * Used for testing.
     */
    void wipeAllContents() throws IOException, GeneralSecurityException {
        for (File f : mDocumentsDir.listFiles()) {
            f.delete();
        }
    }

    @Override
    public Cursor queryRoots(String[] projection) throws FileNotFoundException {
        final MatrixCursor result = new MatrixCursor(resolveRootProjection(projection));
        final RowBuilder row = result.newRow();
        row.add(Root.COLUMN_ROOT_ID, DEFAULT_ROOT_ID);
        row.add(Root.COLUMN_FLAGS, Root.FLAG_SUPPORTS_CREATE | Root.FLAG_LOCAL_ONLY);
        row.add(Root.COLUMN_TITLE, getContext().getString(R.string.app_label));
        row.add(Root.COLUMN_DOCUMENT_ID, DEFAULT_DOCUMENT_ID);
        row.add(Root.COLUMN_ICON, R.drawable.ic_launcher);

        row.add(Root.COLUMN_SUMMARY, "todo: display user id?");

        return result;
    }

    private EncryptedDocument getDocument(long docId) throws GeneralSecurityException {
        return new EncryptedDocument(docId, mDocumentsDir, getContext(), mServiceConnection);
    }

    /**
     * Include metadata for a document in the given result cursor.
     */
    private void includeDocument(MatrixCursor result, long docId)
            throws IOException, GeneralSecurityException {
        final EncryptedDocument doc = getDocument(docId);
        if (!doc.getFile().exists()) {
            throw new FileNotFoundException("Missing document " + docId);
        }

        final JSONObject meta = doc.readMetadata();

        int flags = 0;

        final String mimeType = meta.optString(Document.COLUMN_MIME_TYPE);
        if (Document.MIME_TYPE_DIR.equals(mimeType)) {
            flags |= Document.FLAG_DIR_SUPPORTS_CREATE;
        } else {
            flags |= Document.FLAG_SUPPORTS_WRITE;
        }
        flags |= Document.FLAG_SUPPORTS_DELETE;

        final RowBuilder row = result.newRow();
        row.add(Document.COLUMN_DOCUMENT_ID, meta.optLong(Document.COLUMN_DOCUMENT_ID));
        row.add(Document.COLUMN_DISPLAY_NAME, meta.optString(Document.COLUMN_DISPLAY_NAME));
        row.add(Document.COLUMN_SIZE, meta.optLong(Document.COLUMN_SIZE));
        row.add(Document.COLUMN_MIME_TYPE, mimeType);
        row.add(Document.COLUMN_FLAGS, flags);
        row.add(Document.COLUMN_LAST_MODIFIED, meta.optLong(Document.COLUMN_LAST_MODIFIED));
    }

    @Override
    public String createDocument(String parentDocumentId, String mimeType, String displayName)
            throws FileNotFoundException {
        final long parentDocId = Long.parseLong(parentDocumentId);

        // Allocate the next available ID
        final long childDocId;
        synchronized (mIdLock) {
            final SharedPreferences prefs = getContext()
                    .getSharedPreferences(PREF_NEXT_ID, Context.MODE_PRIVATE);
            childDocId = prefs.getLong(PREF_NEXT_ID, 1);
            if (!prefs.edit().putLong(PREF_NEXT_ID, childDocId + 1).commit()) {
                throw new IllegalStateException("Failed to allocate document ID");
            }
        }

        try {
            initDocument(childDocId, mimeType, displayName);

            // Update parent to reference new child
            final EncryptedDocument parentDoc = getDocument(parentDocId);
            final JSONObject parentMeta = parentDoc.readMetadata();
            parentMeta.accumulate(KEY_CHILDREN, childDocId);
            parentDoc.writeMetadataAndContent(parentMeta, null);

            return String.valueOf(childDocId);

        } catch (IOException e) {
            throw new IllegalStateException(e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        } catch (JSONException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Create document on disk, writing an initial metadata section. Someone
     * might come back later to write contents.
     */
    private void initDocument(long docId, String mimeType, String displayName)
            throws IOException, GeneralSecurityException {
        final EncryptedDocument doc = getDocument(docId);
        if (doc.getFile().exists()) return;

        try {
            final JSONObject meta = new JSONObject();
            meta.put(Document.COLUMN_DOCUMENT_ID, docId);
            meta.put(Document.COLUMN_MIME_TYPE, mimeType);
            meta.put(Document.COLUMN_DISPLAY_NAME, displayName);

            if (Document.MIME_TYPE_DIR.equals(mimeType)) {
                meta.put(KEY_CHILDREN, new JSONArray());
            }

            doc.writeMetadataAndContent(meta, null);
        } catch (JSONException e) {
            throw new IOException(e);
        }
    }

    @Override
    public void deleteDocument(String documentId) throws FileNotFoundException {
        final long docId = Long.parseLong(documentId);

        try {
            // Delete given document, any children documents under it, and any
            // references to it from parents.
            deleteDocumentTree(docId);
            deleteDocumentReferences(docId);

        } catch (IOException e) {
            throw new IllegalStateException(e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Recursively delete the given document and any children under it.
     */
    private void deleteDocumentTree(long docId) throws IOException, GeneralSecurityException {
        final EncryptedDocument doc = getDocument(docId);
        final JSONObject meta = doc.readMetadata();
        try {
            if (Document.MIME_TYPE_DIR.equals(meta.getString(Document.COLUMN_MIME_TYPE))) {
                final JSONArray children = meta.getJSONArray(KEY_CHILDREN);
                for (int i = 0; i < children.length(); i++) {
                    final long childDocId = children.getLong(i);
                    deleteDocumentTree(childDocId);
                }
            }
        } catch (JSONException e) {
            throw new IOException(e);
        }

        if (!doc.getFile().delete()) {
            throw new IOException("Failed to delete " + docId);
        }
    }

    /**
     * Remove any references to the given document, usually when included as a
     * child of another directory.
     */
    private void deleteDocumentReferences(long docId) {
        for (String name : mDocumentsDir.list()) {
            try {
                final long parentDocId = Long.parseLong(name);
                final EncryptedDocument parentDoc = getDocument(parentDocId);
                final JSONObject meta = parentDoc.readMetadata();

                if (Document.MIME_TYPE_DIR.equals(meta.getString(Document.COLUMN_MIME_TYPE))) {
                    final JSONArray children = meta.getJSONArray(KEY_CHILDREN);
                    if (maybeRemove(children, docId)) {
                        Log.d(TAG, "Removed " + docId + " reference from " + name);
                        parentDoc.writeMetadataAndContent(meta, null);

                        getContext().getContentResolver().notifyChange(
                                DocumentsContract.buildChildDocumentsUri(AUTHORITY, name), null,
                                false);
                    }
                }
            } catch (NumberFormatException ignored) {
            } catch (IOException e) {
                Log.w(TAG, "Failed to examine " + name, e);
            } catch (GeneralSecurityException e) {
                Log.w(TAG, "Failed to examine " + name, e);
            } catch (JSONException e) {
                Log.w(TAG, "Failed to examine " + name, e);
            }
        }
    }

    @Override
    public Cursor queryDocument(String documentId, String[] projection)
            throws FileNotFoundException {
        final MatrixCursor result = new MatrixCursor(resolveDocumentProjection(projection));
        try {
            includeDocument(result, Long.parseLong(documentId));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return result;
    }

    @Override
    public Cursor queryChildDocuments(
            String parentDocumentId, String[] projection, String sortOrder)
            throws FileNotFoundException {

        final ExtrasMatrixCursor result = new ExtrasMatrixCursor(
                resolveDocumentProjection(projection));
        result.setNotificationUri(getContext().getContentResolver(),
                DocumentsContract.buildChildDocumentsUri(AUTHORITY, parentDocumentId));

        // TODO: Extra inf below? not for special root folder!
//        result.putString(DocumentsContract.EXTRA_INFO, "bla");

        try {
            final EncryptedDocument doc = getDocument(Long.parseLong(parentDocumentId));
            final JSONObject meta = doc.readMetadata();
            final JSONArray children = meta.getJSONArray(KEY_CHILDREN);
            for (int i = 0; i < children.length(); i++) {
                final long docId = children.getLong(i);
                includeDocument(result, docId);
            }

        } catch (IOException e) {
            throw new IllegalStateException(e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        } catch (JSONException e) {
            throw new IllegalStateException(e);
        }

        return result;
    }

    @Override
    public ParcelFileDescriptor openDocument(
            String documentId, String mode, CancellationSignal signal)
            throws FileNotFoundException {
        final long docId = Long.parseLong(documentId);



        // start proxy activity and wait here for it finishing...
        Intent dialog = new Intent(getContext(), OpenDialogActivity.class);
        dialog.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        dialog.putExtra(OpenDialogActivity.EXTRA_MESSENGER, new Messenger(new Handler(Looper.getMainLooper())));
        dialog.putExtra(OpenDialogActivity.EXTRA_FILENAME, "test");

        getContext().startActivity(dialog);

//        Log.d(TAG, "before wait");
//
        synchronized (mUILock) {
            try {
                mUILock.wait();
            } catch (InterruptedException e) {
               Log.e(TAG, "interrupt", e);
            }
        }
        Log.d(TAG, "after wait");

        try {
            final EncryptedDocument doc = getDocument(docId);
            if ("r".equals(mode)) {
                return startRead(doc);
            } else if ("w".equals(mode) || "wt".equals(mode)) {
                return startWrite(doc);
            } else {
                throw new IllegalArgumentException("Unsupported mode: " + mode);
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Kick off a thread to handle a read request for the given document.
     * Internally creates a pipe and returns the read end for returning to a
     * remote process.
     */
    private ParcelFileDescriptor startRead(final EncryptedDocument doc) throws IOException {
        final ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createReliablePipe();
        final ParcelFileDescriptor readEnd = pipe[0];
        final ParcelFileDescriptor writeEnd = pipe[1];

        new Thread() {
            @Override
            public void run() {
                try {
                    doc.readContent(writeEnd);
                    Log.d(TAG, "Success reading " + doc);
                    closeQuietly(writeEnd);
                } catch (IOException e) {
                    Log.w(TAG, "Failed reading " + doc, e);
                    closeWithErrorQuietly(writeEnd, e.toString());
                } catch (GeneralSecurityException e) {
                    Log.w(TAG, "Failed reading " + doc, e);
                    closeWithErrorQuietly(writeEnd, e.toString());
                }
            }
        }.start();

        return readEnd;
    }

    /**
     * Kick off a thread to handle a write request for the given document.
     * Internally creates a pipe and returns the write end for returning to a
     * remote process.
     */
    private ParcelFileDescriptor startWrite(final EncryptedDocument doc) throws IOException {
        final ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createReliablePipe();
        final ParcelFileDescriptor readEnd = pipe[0];
        final ParcelFileDescriptor writeEnd = pipe[1];

        new Thread() {
            @Override
            public void run() {
                try {
                    // get already written metadata from file
                    final JSONObject meta = doc.readMetadata();
                    doc.writeMetadataAndContent(meta, readEnd);
                    Log.d(TAG, "Success writing " + doc);
                    closeQuietly(readEnd);
                } catch (IOException e) {
                    Log.w(TAG, "Failed writing " + doc, e);
                    closeWithErrorQuietly(readEnd, e.toString());
                } catch (GeneralSecurityException e) {
                    Log.w(TAG, "Failed writing " + doc, e);
                    closeWithErrorQuietly(readEnd, e.toString());
                }
            }
        }.start();

        return writeEnd;
    }

    /**
     * Maybe remove the given value from a {@link JSONArray}.
     *
     * @return if the array was mutated.
     */
    private static boolean maybeRemove(JSONArray array, long value) throws JSONException {
        boolean mutated = false;
        int i = 0;
        while (i < array.length()) {
            if (value == array.getLong(i)) {
                array.remove(i);
                mutated = true;
            } else {
                i++;
            }
        }
        return mutated;
    }

    /**
     * Simple extension of {@link MatrixCursor} that makes it easy to provide a
     * {@link Bundle} of extras.
     */
    private static class ExtrasMatrixCursor extends MatrixCursor {
        private Bundle mExtras;

        public ExtrasMatrixCursor(String[] columnNames) {
            super(columnNames);
        }

        public void putString(String key, String value) {
            if (mExtras == null) {
                mExtras = new Bundle();
            }
            mExtras.putString(key, value);
        }

        @Override
        public Bundle getExtras() {
            return mExtras;
        }
    }
}
