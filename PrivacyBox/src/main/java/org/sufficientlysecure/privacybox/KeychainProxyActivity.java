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
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentSender;
import android.os.Bundle;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;

/**
 * We need to start activites that return data back to a starting Activity with onActivityResult().
 * Thus we can not directly start the PendingIntent from the ContentProvider's context because there is no
 * onActivityResult() available to get the results.
 * <p/>
 * This activity is just a proxy to start the PendingIntent and return the results back via
 * a Messenger to the ContentProvider.
 */
public class KeychainProxyActivity extends Activity {

    public static final String EXTRA_PENDING_INTENT = "pi";
    public static final String EXTRA_MESSENGER = "messenger";

    public static final String RESULT_BUNDLE_DATA_INTENT = "intent";

    public static final int REQUEST_CODE = 42;

    Messenger mMessenger;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mMessenger = getIntent().getParcelableExtra(EXTRA_MESSENGER);

        // directly start pending intent
        PendingIntent pi = getIntent().getParcelableExtra(EXTRA_PENDING_INTENT);
        try {
            KeychainProxyActivity.this.startIntentSenderFromChild(
                    KeychainProxyActivity.this, pi.getIntentSender(),
                    REQUEST_CODE, null, 0, 0, 0);
        } catch (IntentSender.SendIntentException e) {
            Log.e(VaultProvider.TAG, "SendIntentException", e);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        Log.d(VaultProvider.TAG, "onActivityResult resultCode (-1 is OKAY): " + resultCode);

        if (resultCode == RESULT_OK) {
            /*
            * The data originally given to one of the methods above, is again
            * returned here to be used when calling the method again after user
            * interaction. The Intent now also contains results from the user
            * interaction, for example selected key ids.
            */
            switch (requestCode) {
                case REQUEST_CODE: {
                    Bundle bundle = new Bundle();
                    bundle.putParcelable(RESULT_BUNDLE_DATA_INTENT, data);
                    Message msg = Message.obtain();
                    msg.setData(bundle);
                    try {
                        mMessenger.send(msg);
                    } catch (RemoteException e) {
                        Log.e(VaultProvider.TAG,
                                "RemoteException when sending back message to ContentProvider", e);
                    }
                    break;
                }
            }
        }

        // finish proxy
        finish();
    }

}
