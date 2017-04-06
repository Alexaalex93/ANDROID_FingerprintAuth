package com.company.alex.fingerprintauth;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.CancellationSignal;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.widget.TextView;

/**
 * Created by Alex on 06/04/2017.
 */

public class FingerprintHandler extends FingerprintManager.AuthenticationCallback {

    private Context mContext;

    public FingerprintHandler(Context context) {
        mContext = context;
    }

    //Iniciar la autenticación del usuario
    public void startAuth(FingerprintManager manager, FingerprintManager.CryptoObject cryptoObject) {

        CancellationSignal cancellationSignal = new CancellationSignal();

        if (ActivityCompat.checkSelfPermission(mContext, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            return;
        }
        manager.authenticate(cryptoObject, cancellationSignal, 0, this, null);

    }


    public void update(String e, Boolean success) {
        TextView textView = (TextView) ((Activity) mContext).findViewById(R.id.errorText);
        textView.setText(e);
        textView.setTextColor(ContextCompat.getColor(mContext, R.color.errorText));
        if (success) {
            textView.setTextColor(ContextCompat.getColor(mContext, R.color.colorPrimaryDark));
            Intent intent = new Intent(mContext, HomeActivity.class);
            mContext.startActivity(intent);
        }
    }

    @Override
    public void onAuthenticationError(int errorCode, CharSequence errString) {
        this.update("Error al autenticar" + errString, false);
    }

    @Override
    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
        this.update("Necesitas ayuda", false);
    }

    @Override
    public void onAuthenticationFailed() {
        this.update("Fallo en el proceso", false);
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        this.update("Autenticacion correcta", true);
    }
}
