package com.company.alex.fingerprintauth;

import android.Manifest;
import android.app.KeyguardManager;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.annotation.Nullable;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.widget.TextView;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * Created by Alex on 06/04/2017.
 */

public class FingerprintActivity extends AppCompatActivity{

    //Contenedor donde se guarda la huella
    private KeyStore keyStore;
    //Identificador para saber a qué huella nos referimos
    private static final String KEY_NAME = "alexFingerPrint";
    //Objeto que lo cifra
    private Cipher cipher;
    private TextView textView;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_fingerprint);

        //Keyguard Manager & Fingerprint Manager
        KeyguardManager keyguardManager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
        FingerprintManager fingerprintManager = (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);

        textView = (TextView) findViewById(R.id.errorText);

        //Comprobar si tiene sensor de huellas. Si no tiene mensaje de error, aunque lo ideal sería pasar a otra Activity
        if (!fingerprintManager.isHardwareDetected())
            textView.setText(R.string.error_message);
        else{
            if (ActivityCompat.checkSelfPermission(this, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
                //El dispositivo si tiene sensor, pero no permiso otorgado
                textView.setText(R.string.error_permission);
            } else {
                //Comprobar si tiene alguna huella registrada
                if (!fingerprintManager.hasEnrolledFingerprints()) {
                    textView.setText(R.string.error_registro_huella);
                } else {
                    //Comprobar si tiene seguridad en la pantalla bloqueada
                    if (!keyguardManager.isKeyguardSecure()) {
                        textView.setText(R.string.error_pantalla_bloqueo);
                    } else {
                        generateKey();
                        if(cipherInit()) {
                            FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);
                            FingerprintHandler helper = new FingerprintHandler(this);
                            helper.startAuth(fingerprintManager, cryptoObject);
                        }
                    }
                }
            }
        }
    }

    protected void generateKey() { //Estamos creando una clave que solo nuestra huella puede descifrar. TODO APUNTE PARA APP

        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
        } catch (Exception e) {
            e.printStackTrace();
        }

        KeyGenerator keyGenerator; //Clave para cifrar el contenido de la app
        try {
            //aLGORITMO PARA PDOER CIFRAR LA CLAVE. AES ES DE LOS MAS SEGUROS
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException("Error al generar una clave", e);
        }

        try {
            keyStore.load(null);
            /**
             * Primero le pasas una clave (como si fuera una clave pública)
             * Luego cual es el proposito
             * Le decimos qcomo queremos los bloques. Si utilizas un block_mode solo se puede desencriptar usando ese block mode
             */

            keyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | CertificateException | IOException e) {
            throw new RuntimeException(e);
        }
    }
    public boolean cipherInit() { //Para encriptar
        try {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES //Cogemos la clave a traves del alia y nos ponemos en modo encriptacion
                    + "/" + KeyProperties.BLOCK_MODE_CBC
                    + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Error al acceder al Cipher Object");
        }

        try {
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey(KEY_NAME, null);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return true;
        } catch (KeyPermanentlyInvalidatedException e) {
            return false;
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | IOException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Error al inicializar cipher", e);
        }

    }
}
