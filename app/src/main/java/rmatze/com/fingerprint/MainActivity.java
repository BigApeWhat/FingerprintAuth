package rmatze.com.fingerprint;

import android.Manifest;
import android.app.KeyguardManager;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.preference.PreferenceManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

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
import javax.crypto.spec.IvParameterSpec;

import rmatze.com.fingerprint.R;

public class MainActivity extends AppCompatActivity implements FingerprintHelper.FingerprintHelperListener {

    String TAG = getClass().getName();

    private KeyguardManager mKeyguardManager;
    private FingerprintManager mFingerprintManager;
    private KeyStore mKeyStore;
    private KeyGenerator mKeyGenerator;
    private Cipher mCipher;
    private SharedPreferences mSharedPreferences;
    private FingerprintManager.CryptoObject mCryptoObject;
    private FingerprintHelper mFingerprintHelper;
    private FingerprintAuthenticationDialogFragment mFragment;

    private static final String KEYSTORE = "AndroidKeyStore";
    /** Alias for our key in the Android Key Store */
    private static final String KEY_NAME = "my_key";
    private static final String PREFERENCES_KEY_IV = "iv";
    private static final String PREFERENCES_KEY_EMAIL = "email";
    private static final String PREFERENCES_KEY_PASS = "pass";
    private static final String DIALOG_FRAGMENT_TAG = "myFragment";

    private boolean mEncrypting;

    TextView mResultTextview;
    EditText mEditText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button encryptBtn = (Button) findViewById(R.id.encrypt_btn);
        encryptBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if(initCipher(Cipher.ENCRYPT_MODE) && initCryptObject()) {
                    mEncrypting = true;

                    mFragment = new FingerprintAuthenticationDialogFragment();
                    mFragment.setFingerprintManager(mFingerprintManager);
                    mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipher));
                    boolean useFingerprintPreference = mSharedPreferences
                            .getBoolean(getString(R.string.use_fingerprint_to_authenticate_key),
                                    true);
                    if (useFingerprintPreference) {
                        mFragment.setStage(
                                FingerprintAuthenticationDialogFragment.Stage.FINGERPRINT);
                    } else {
                        mFragment.setStage(
                                FingerprintAuthenticationDialogFragment.Stage.PASSWORD);
                    }
                    mFragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);
                }
            }
        });
        Button decryptBtn = (Button) findViewById(R.id.decrypt_btn);
        decryptBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if(initCipher(Cipher.DECRYPT_MODE) && initCryptObject()) {
                    mEncrypting = false;

                    mFragment = new FingerprintAuthenticationDialogFragment();
                    mFragment.setFingerprintManager(mFingerprintManager);
                    mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipher));
                    boolean useFingerprintPreference = mSharedPreferences
                            .getBoolean(getString(R.string.use_fingerprint_to_authenticate_key),
                                    true);
                    if (useFingerprintPreference) {
                        mFragment.setStage(
                                FingerprintAuthenticationDialogFragment.Stage.FINGERPRINT);
                    } else {
                        mFragment.setStage(
                                FingerprintAuthenticationDialogFragment.Stage.PASSWORD);
                    }
                    mFragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);
                }
            }
        });
        mResultTextview = (TextView) findViewById(R.id.result_textview);
        mEditText = (EditText) findViewById(R.id.edittext);

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            Log.d(TAG, "This Android version does not support fingerprint authentication.");
            return;
        }

        mKeyguardManager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
        if (!mKeyguardManager.isKeyguardSecure()) {
            // Show a message that the user hasn't set up a fingerprint or lock screen.
            Toast.makeText(this,
                    "Secure lock screen hasn't set up.\n"
                            + "Go to 'Settings -> Security -> Fingerprint' to set up a fingerprint",
                    Toast.LENGTH_LONG).show();
            return;
        }

        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.USE_FINGERPRINT)
                != PackageManager.PERMISSION_GRANTED) {
            return;
        }

        mFingerprintManager = (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);
        if (!mFingerprintManager.hasEnrolledFingerprints()) {
            // This happens when no fingerprints are registered.
            Toast.makeText(this,
                    "Go to 'Settings -> Security -> Fingerprint' and register at least one fingerprint",
                    Toast.LENGTH_LONG).show();
            return;
        }

        mSharedPreferences = PreferenceManager.getDefaultSharedPreferences(this);

        createKey();
    }

    /**
     * Creates a symmetric key in the Android Key Store which can only be used after the user has
     * authenticated with fingerprint.
     */
    public void createKey() {
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of
        // enrolled fingerprints has changed.
        try {
            mKeyStore = KeyStore.getInstance(KEYSTORE);
            mKeyStore.load(null); // Create empty keystore
            // Set the alias of the entry in Android KeyStore where the key will appear
            // and the constrains (purposes) in the constructor of the Builder
            mKeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
            mKeyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT |
                            KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    // Require the user to authenticate with a fingerprint to authorize every use
                    // of the key
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            mKeyGenerator.generateKey();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException
                | CertificateException | IOException e) {
            throw new RuntimeException(e);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    /**
     * Initialize the {@link Cipher} instance with the created key in the {@link #createKey()}
     * method.
     *
     * @return {@code true} if initialization is successful, {@code false} if the lock screen has
     * been disabled or reset after the key was generated, or if a fingerprint got enrolled after
     * the key was generated.
     */
    private boolean initCipher(int mode) {
        try {
            mKeyStore.load(null);
            SecretKey key = (SecretKey) mKeyStore.getKey(KEY_NAME, null);
            mCipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7);
            if (mode == Cipher.ENCRYPT_MODE) {
                mCipher.init(mode, key);

                SharedPreferences.Editor editor = mSharedPreferences.edit();
                editor.putString(PREFERENCES_KEY_IV, Base64.encodeToString(mCipher.getIV(), Base64.NO_WRAP));
                editor.commit();
            } else {
                byte[] iv = Base64.decode(mSharedPreferences.getString(PREFERENCES_KEY_IV, ""), Base64.NO_WRAP);
                IvParameterSpec ivspec = new IvParameterSpec(iv);
                mCipher.init(mode, key, ivspec);
            }
            return true;
        } catch (KeyPermanentlyInvalidatedException e) {
            return false;
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | IOException
                | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return false;
    }

    private boolean initCryptObject() {
        Log.d(TAG, "Initializing crypt object...");
        try {
            mCryptoObject = new FingerprintManager.CryptoObject(mCipher);
            return true;
        } catch (Exception ex) {
            Log.d(TAG, ex.getMessage());
        }
        return false;
    }

    @Override
    public void authenticationFailed(String error) {
        Log.d(TAG, error);
    }

    @Override
    public void authenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        Log.d(TAG, "Authentication succeeded!");
        mCipher = result.getCryptoObject().getCipher();

        if (mEncrypting) {
            String textToEncrypt = mEditText.getText().toString();
            if(textToEncrypt != null && !textToEncrypt.isEmpty()) {
                encryptString(textToEncrypt);
            } else {
                Toast.makeText(this, "Enter some text", Toast.LENGTH_SHORT).show();
            }
        }
        else {
            String encryptedText = readSharedPreference(PREFERENCES_KEY_PASS);
            decryptString(encryptedText);
        }
    }

    public void encryptString(String initialText) {
        Log.d(TAG,"Encrypting...");
        try {
            byte[] bytes = mCipher.doFinal(initialText.getBytes());
            String encryptedText = Base64.encodeToString(bytes, Base64.NO_WRAP);

            writeSharedPreference(PREFERENCES_KEY_PASS, encryptedText);

            mResultTextview.setText(encryptedText);
        } catch (Exception e) {
            Log.d(TAG, e.getMessage());
        }
    }

    public void decryptString(String cipherText) {
        Log.d(TAG,"Decrypting...");
        try {
            byte[] bytes = Base64.decode(cipherText, Base64.NO_WRAP);
            String finalText = new String(mCipher.doFinal(bytes));
            mResultTextview.setText(finalText);
        } catch (Exception e) {
            Log.d(TAG, e.getMessage());
        }
    }

    public void writeSharedPreference(String name, String value) {
        SharedPreferences.Editor editor = mSharedPreferences.edit();
        editor.putString(name, value);
        editor.apply();
    }

    public String readSharedPreference(String name) {
        return mSharedPreferences.getString(name, "");
    }
}
