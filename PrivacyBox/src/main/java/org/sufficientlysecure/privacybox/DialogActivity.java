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
import android.os.Bundle;
import android.os.Messenger;
import android.util.Log;
import android.view.ContextThemeWrapper;

/**
 * We can not directly create a dialog on the context provided inside the content provider.
 * This activity encapsulates a DialogFragment to emulate a dialog.
 */
public class DialogActivity extends Activity {

    public static final String EXTRA_MESSENGER = "messenger";

    public static final String RESULT_BUNDLE_DATA_INTENT = "intent";

    Messenger mMessenger;

    MyDialogFragment mDialogFragment;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mMessenger = getIntent().getParcelableExtra(EXTRA_MESSENGER);

        // this activity itself has no content view (see manifest)

        // Create an instance of the fragment
        mDialogFragment = new MyDialogFragment();
        // start it
        mDialogFragment.show(getFragmentManager(), "dialog");
    }

    public static class MyDialogFragment extends DialogFragment {
        private static final String ARG_MESSENGER = "messenger";
        private static final String ARG_NAME = "name";

        public static final int MESSAGE_OKAY = 1;
        public static final int MESSAGE_CANCEL = 2;

        public static final String MESSAGE_DATA_USER_ID = "user_id";

        private Messenger mMessenger;

//        public static MyDialogFragment newInstance(Messenger messenger) {
//
//            MyDialogFragment frag = new MyDialogFragment();
//            Bundle args = new Bundle();
////            args.putParcelable(ARG_MESSENGER, messenger);
////            args.putString(ARG_NAME, predefinedName);
//            frag.setArguments(args);
//
//            return frag;
//        }

        /**
         * Creates dialog
         */
        @Override
        public Dialog onCreateDialog(Bundle savedInstanceState) {
            final Activity activity = getActivity();
//            mMessenger = getArguments().getParcelable(ARG_MESSENGER);
//            String predefinedName = getArguments().getString(ARG_NAME);

            // hack to get holo design (which is not automatically applied due to activity's Theme.NoDisplay
            ContextThemeWrapper context = new ContextThemeWrapper(getActivity(),
                    android.R.style.Theme_DeviceDefault_Light_Dialog);
            AlertDialog.Builder alert = new AlertDialog.Builder(context);

            alert.setTitle("rt");
            alert.setMessage("test");

//            LayoutInflater inflater = activity.getLayoutInflater();
//            View view = inflater.inflate(R.layout.add_user_id_dialog, null);
//            alert.setView(view);


            alert.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int id) {
                    dismiss();

//                    Bundle data = new Bundle();
//                    String userId = KeyRing.createUserId(mName.getText().toString(),
//                            mEmail.getText().toString(), mComment.getText().toString());
//                    data.putString(MESSAGE_DATA_USER_ID, userId);
//                    sendMessageToHandler(MESSAGE_OKAY, data);
                }
            });

            alert.setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int id) {
                    dialog.cancel();
                }
            });

            return alert.show();
        }

        //        @Override
//        public void onCancel(DialogInterface dialog) {
//            super.onCancel(dialog);
//
//            dismiss();
//            sendMessageToHandler(MESSAGE_CANCEL);
//        }
//
        @Override
        public void onDismiss(DialogInterface dialog) {
            super.onDismiss(dialog);
            Log.d(VaultProvider.TAG, "onDismiss");

            // hide keyboard on dismiss
            getActivity().finish();
        }


//        /**
//         * Send message back to handler which is initialized in a activity
//         *
//         * @param what Message integer you want to send
//         */
//        private void sendMessageToHandler(Integer what) {
//            Message msg = Message.obtain();
//            msg.what = what;
//
//            try {
//                mMessenger.send(msg);
//            } catch (RemoteException e) {
//                Log.w(Constants.TAG, "Exception sending message, Is handler present?", e);
//            } catch (NullPointerException e) {
//                Log.w(Constants.TAG, "Messenger is null!", e);
//            }
//        }
//
//        /**
//         * Send message back to handler which is initialized in a activity
//         *
//         * @param what Message integer you want to send
//         */
//        private void sendMessageToHandler(Integer what, Bundle data) {
//            Message msg = Message.obtain();
//            msg.what = what;
//            if (data != null) {
//                msg.setData(data);
//            }
//
//            try {
//                mMessenger.send(msg);
//            } catch (RemoteException e) {
//                Log.w(Constants.TAG, "Exception sending message, Is handler present?", e);
//            } catch (NullPointerException e) {
//                Log.w(Constants.TAG, "Messenger is null!", e);
//            }
//        }

    }

}
