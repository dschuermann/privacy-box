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

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.app.DialogFragment;
import android.content.DialogInterface;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.text.Spannable;
import android.text.SpannableString;
import android.text.SpannedString;
import android.text.TextUtils;
import android.text.style.StyleSpan;
import android.util.Log;
import android.view.ContextThemeWrapper;

/**
 * We can not directly create a dialog on the context provided inside the content provider.
 * This activity encapsulates a DialogFragment to emulate a dialog.
 */
public class OpenDialogActivity extends Activity {

    public static final String EXTRA_MESSENGER = "messenger";
    public static final String EXTRA_FILENAME = "filename";

    public static final int MSG_CANCEL = 1;
    public static final int MSG_DECRYPT_OPEN = 2;
    public static final int MSG_GET_ENCRYPTED = 3;

    MyDialogFragment mDialogFragment;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // this activity itself has no content view (see manifest)

        mDialogFragment = new MyDialogFragment();
        // give all extras through to the fragment
        mDialogFragment.setArguments(getIntent().getExtras());

        mDialogFragment.show(getFragmentManager(), "dialog");
    }

    public static class MyDialogFragment extends DialogFragment {

        private Messenger mMessenger;

        /**
         * Creates dialog
         */
        @Override
        public Dialog onCreateDialog(Bundle savedInstanceState) {
            mMessenger = getArguments().getParcelable(EXTRA_MESSENGER);
            String filename = getArguments().getString(EXTRA_FILENAME);

            // hack to get holo design (which is not automatically applied due to activity's Theme.NoDisplay
            ContextThemeWrapper context = new ContextThemeWrapper(getActivity(),
                    android.R.style.Theme_DeviceDefault_Light_Dialog);
            AlertDialog.Builder alert = new AlertDialog.Builder(context);

            final SpannableString filenameBold = new SpannableString(filename);
            StyleSpan boldSpan = new StyleSpan(Typeface.BOLD);
            filenameBold.setSpan(boldSpan, 0, filenameBold.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);

            SpannedString message = (SpannedString) TextUtils.concat(filenameBold, "\n\n", getString(R.string.open_dialog_text));

            alert.setTitle(R.string.open_dialog_title);
            alert.setMessage(message);

            alert.setPositiveButton(R.string.open_dialog_decrypt_open_button, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int id) {
                    dismiss();
                    sendMessageToHandler(MSG_DECRYPT_OPEN);
                }
            });

            alert.setNegativeButton(R.string.open_dialog_get_encrypted_button, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int id) {
                    dismiss();
                    sendMessageToHandler(MSG_GET_ENCRYPTED);
                }
            });

            return alert.show();
        }

        @Override
        public void onCancel(DialogInterface dialog) {
            super.onCancel(dialog);

            dismiss();
            sendMessageToHandler(MSG_CANCEL);
        }

        @Override
        public void onDismiss(DialogInterface dialog) {
            super.onDismiss(dialog);
            Log.d(VaultProvider.TAG, "onDismiss");

            getActivity().finish();
        }

        /**
         * Send message back to handler which is initialized in a activity
         *
         * @param what Message integer you want to send
         */
        private void sendMessageToHandler(Integer what) {
            Message msg = Message.obtain();
            msg.what = what;

            try {
                mMessenger.send(msg);
            } catch (RemoteException e) {
                Log.w(VaultProvider.TAG, "Exception sending message, Is handler present?", e);
            } catch (NullPointerException e) {
                Log.w(VaultProvider.TAG, "Messenger is null!", e);
            }
        }

    }

}
