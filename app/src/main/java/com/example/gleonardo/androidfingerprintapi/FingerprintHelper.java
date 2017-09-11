package com.example.gleonardo.androidfingerprintapi;

import android.annotation.TargetApi;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;

/**
 * Created by gleonardo on 11/09/2017.
 */
@TargetApi(Build.VERSION_CODES.M)
public class FingerprintHelper extends FingerprintManager.AuthenticationCallback {

    private FingerprintHelperListener listener;
    private CancellationSignal cancellationSignal;

    public FingerprintHelper(FingerprintHelperListener listener){
        this.listener = listener;
    }

    public void startAuth(FingerprintManager manager, FingerprintManager.CryptoObject cryptoObject){
        cancellationSignal = new CancellationSignal();

        try{
            manager.authenticate(cryptoObject, cancellationSignal,0, this, null);
        } catch (SecurityException ex){
            listener.authenticationFailed("An error occurred: \n" + ex.getMessage());
        } catch (Exception ex) {
            listener.authenticationFailed("An error occurred\n" + ex.getMessage());
        }
    }

    public void cancel(){
        if (cancellationSignal != null){
            cancellationSignal.cancel();
        }
    }

    @Override
    public void onAuthenticationError(int errMsgId, CharSequence errString) {
        listener.authenticationFailed("Authentication error\n" + errString);
    }

    @Override
    public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
        listener.authenticationFailed("Authentication help\n" + helpString);
    }

    @Override
    public void onAuthenticationFailed() {
        listener.authenticationFailed("Authentication failed.");
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        listener.authenticationSucceeded(result);
    }

    interface FingerprintHelperListener{
        public void authenticationFailed(String error);
        public void authenticationSucceeded(FingerprintManager.AuthenticationResult result);
    }
}
