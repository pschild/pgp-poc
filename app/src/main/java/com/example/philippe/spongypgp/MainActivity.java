package com.example.philippe.spongypgp;

import android.content.Context;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;

import com.example.philippe.spongypgp.jdamico.PgpHelper;
import com.example.philippe.spongypgp.jdamico.RSAKeyPairGenerator;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openpgp.PGPException;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class MainActivity extends AppCompatActivity {

    private boolean isArmored = true;
    private String id = "bob";
    private String passwd = "bob";
    private boolean integrityCheck = true;

    private String pubKeyFile = "pub.dat";
    private String privKeyFile = "secret.dat";

    private String plainTextFile = "plain-text.txt";
    private String cipherTextFile = "cypher-text.dat";
    private String decPlainTextFile = "dec-plain-text.txt";
    private String signatureFile = "signature.txt";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        createStaticFiles();
    }

    /**
     * files will be stored in DEVICE_ROOT/data/data/<APP_NAME>/files
     */
    private void createStaticFiles() {
        FileOutputStream outputStream;

        String content = "Eine Nachricht von Bob an Alice.";
        try {
            outputStream = openFileOutput(plainTextFile, Context.MODE_PRIVATE);
            outputStream.write(content.getBytes());
            outputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        content = "" +
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "Version: OpenPGP.js v2.6.2\n" +
                "Comment: https://openpgpjs.org\n" +
                "\n" +
                "xsBNBFt6YM4BCACuHKj/U6dFjtFbB7TJVMbz/cOTg4uwaNiAMMpQdEZEqQiS\n" +
                "u+i0D2T/wbjdiyX7Ynsv0tNXH2f3rQMRVKuQl7E2SCfJDlW+gzDzUHFFxme5\n" +
                "PRiCalMtESGN/Tq132HPxw5MyoVNN8p0iNRBsxr6J3irC7DLBGsUXcoXxZCO\n" +
                "r0acJJgTpp63CbL8xRaHoZ0QLhpbwe+5N2CTXO+l8gegYAIiGgAje83MYCfU\n" +
                "N1fWEbpa+ribG2+XddxJxrfftRoAP8hn7AHDoasDAoxdDAxVluXwykXehZDq\n" +
                "rZNSOhKF9ZTQtqzEs6ktpyIY+MNlAbAXNrRxf0LXXwf5j/rxcammEZ/JABEB\n" +
                "AAHNCGFsaWNlIDw+wsB1BBABCAApBQJbemDTBgsJBwgDAgkQ4IvmQBYaqBME\n" +
                "FQgKAgMWAgECGQECGwMCHgEAAL4hCACYVAygG37XHCrHbxu52l61Rv7+1tRC\n" +
                "4B0iBdc4vryQUr1n6IHf/bhCezmbj5kTdSXL4LngGjpIyETL7vAoa/9Vh4U9\n" +
                "KRgvCMtf38YH4dSW+OclxrQmKzKjBhHZ83hbH72CtsnDNN3HnrXhuvRu5X2F\n" +
                "7qGcsJi1xEwbblDUBDGcnoicmON8v77+ftPqv7HUAMr7Pujw/61ejb3gODXK\n" +
                "WIGr+j8ND5EYA0Aiqgi+AADw6R5zacWczFKYEf08eDKVL1A8Jz3CGpQxI0dr\n" +
                "EkLJ4v1MPXLWBWswTuyexnqoMRx9BSNBz4hv3hvVRDx8hG0b8IyK2FcMDckN\n" +
                "ibEEWThhJWTyzsBNBFt6YNMBCACNekBdexxUJYE28mvDsSicVdtQmqSsSJY7\n" +
                "DPPYZ++FvFFvjE6U+nJeHjyhfJIGE94J56tD4ztxYr9KzNwBhhR+HT4CSfTO\n" +
                "56Ntr8WEaJeeV+UeGG4MrI5czmV/cRipgVdbRynDSafKphhxezKxZJDrEzSp\n" +
                "bUjEf2VDyVesRt5Ov3za5mzuO5XFms5zGOqcFf76AXfw9wmvhydKvLOVLJXj\n" +
                "RUy+21vR5BdDCKzM3cWlDn09IbYP7L/LRfV/aWG1A29gnaQAsnhVCyhSa2DI\n" +
                "JH9EGWEROnaNKEehvHXekpFpkPuw3MZQVAjff3uhYfLa1EKAnLz+GePu6zEi\n" +
                "8KqXYFrrABEBAAHCwF8EGAEIABMFAlt6YNMJEOCL5kAWGqgTAhsMAADSLAf+\n" +
                "Kn4AEFSJkudJmveFiAk67n/6toRyNcru6xmKJZv6UZmCbDSVFVQc0E5cZ92L\n" +
                "i+sgQCHAqS2VGRAPOgIz1+65h/hQQ3gFgLniyQv8dCxgZ26EnhTynq7k3x44\n" +
                "6FMHFNAcc5c24pWEUxzU9IRhdyaXobxwSs7fx1moilU8L/dobPwX0BLdcQtD\n" +
                "/rkb2cg2GBIWDkD5pCCwf0gU6dNQDhcsUfxPGCm4+0Aw7Uito0oanTu89yTu\n" +
                "+5if6H8ieiFmPukBe/aWKGWllaIm5kZdbHByLwAO2WfipgIwfrCG6NQJRYk5\n" +
                "XrhNnbncuSM3YpBvDLBQ1za8D1MhXYeifZyG6ualDA==\n" +
                "=WgY8\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        try {
            outputStream = openFileOutput("pub_alice.dat", Context.MODE_PRIVATE);
            outputStream.write(content.getBytes());
            outputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        content = "" +
                "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Version: OpenPGP.js v2.6.2\n" +
                "Comment: https://openpgpjs.org\n" +
                "\n" +
                "xcMGBFt6YM4BCACuHKj/U6dFjtFbB7TJVMbz/cOTg4uwaNiAMMpQdEZEqQiS\n" +
                "u+i0D2T/wbjdiyX7Ynsv0tNXH2f3rQMRVKuQl7E2SCfJDlW+gzDzUHFFxme5\n" +
                "PRiCalMtESGN/Tq132HPxw5MyoVNN8p0iNRBsxr6J3irC7DLBGsUXcoXxZCO\n" +
                "r0acJJgTpp63CbL8xRaHoZ0QLhpbwe+5N2CTXO+l8gegYAIiGgAje83MYCfU\n" +
                "N1fWEbpa+ribG2+XddxJxrfftRoAP8hn7AHDoasDAoxdDAxVluXwykXehZDq\n" +
                "rZNSOhKF9ZTQtqzEs6ktpyIY+MNlAbAXNrRxf0LXXwf5j/rxcammEZ/JABEB\n" +
                "AAH+CQMIB4P6X0BNj0Bgchtw66wHOM1zLcqGH2cJrrdgXSyyV3doOxetMAqJ\n" +
                "YVaJlVqDvj6itK4g/bZbPYwwex/d5vKaOpbvCpbZfCVH7fOnFw4lFarqybNQ\n" +
                "3F0QA0Uw/fWvv6qcEnbGcNQmoyzN88Ci1miJY8TUnLDe0xL+IkNVCezXFUz4\n" +
                "cyC1493+RjDTISlAGzh/+KZPgTwyUDPpDwcPD+XcsPzfuPoJGS2GqYc3OEv8\n" +
                "yZ03sjPgIgQmH3/qrIqAqERraTIIaQYkthVThdwOGBGUp2CgOut87t+Cuwtz\n" +
                "3tuA/t5tbL/81fzHePMqmKONLjWuI6FFzM4zVfu+qt5SHJ9bXFg6ENnHk81G\n" +
                "vuWaoLTb4Pmmnmv1o/B0zLIAo55QuLBguQMuV40kd6YTlTnEurHfNeOl+5eJ\n" +
                "NlHScayUlKkry2qvJnugodiOIWBUtTV3HO5XGGW3Atd9iZ2ywd92yUaJdgC3\n" +
                "xU++0Rtdvd59gHVs738ptosGRWSC3y0Of6IY4yJ0xLwbKnThiioDFMKN+BVe\n" +
                "5hAtqX0QPLYidQjWdTi9LJUWpSsE2rwk32NFEG1rsH/NwBFW7AKT6RtZjHFQ\n" +
                "woUxOy6TJeH3pkht62fXi3VPLAZsrVe2+XT3+guVgLlUkklIMFmxIJBWfwf1\n" +
                "yqvitpM7FnyBB7s1CV7B3c8xOCNl1t8ncmKptMIevS57bjHV2y8e7TctIX+V\n" +
                "sFU0CN4gI5kkze/ThM5IPXgY8d05liaH+3nzJr6nJPx4aQtR7QBWWtR8dvoy\n" +
                "8iTHAa8DTcqbMhEBYwa+eknhr8lo4DoA9HGIj9dPlrmfUFI61XygfElcvOJf\n" +
                "O4KXjR+x/XCGHbb0g9NFjzJuK3dclmDi6c/rHuFruyW3bhB9MDIE11tNLHDT\n" +
                "KzUHtZklBHN9JWf9b+Qq+rMTSgZdY1cEzQhhbGljZSA8PsLAdQQQAQgAKQUC\n" +
                "W3pg0wYLCQcIAwIJEOCL5kAWGqgTBBUICgIDFgIBAhkBAhsDAh4BAAC+IQgA\n" +
                "mFQMoBt+1xwqx28budpetUb+/tbUQuAdIgXXOL68kFK9Z+iB3/24Qns5m4+Z\n" +
                "E3Uly+C54Bo6SMhEy+7wKGv/VYeFPSkYLwjLX9/GB+HUlvjnJca0JisyowYR\n" +
                "2fN4Wx+9grbJwzTdx5614br0buV9he6hnLCYtcRMG25Q1AQxnJ6InJjjfL++\n" +
                "/n7T6r+x1ADK+z7o8P+tXo294Dg1yliBq/o/DQ+RGANAIqoIvgAA8Okec2nF\n" +
                "nMxSmBH9PHgylS9QPCc9whqUMSNHaxJCyeL9TD1y1gVrME7snsZ6qDEcfQUj\n" +
                "Qc+Ib94b1UQ8fIRtG/CMithXDA3JDYmxBFk4YSVk8sfDBgRbemDTAQgAjXpA\n" +
                "XXscVCWBNvJrw7EonFXbUJqkrEiWOwzz2GfvhbxRb4xOlPpyXh48oXySBhPe\n" +
                "CeerQ+M7cWK/SszcAYYUfh0+Akn0zuejba/FhGiXnlflHhhuDKyOXM5lf3EY\n" +
                "qYFXW0cpw0mnyqYYcXsysWSQ6xM0qW1IxH9lQ8lXrEbeTr982uZs7juVxZrO\n" +
                "cxjqnBX++gF38PcJr4cnSryzlSyV40VMvttb0eQXQwiszN3FpQ59PSG2D+y/\n" +
                "y0X1f2lhtQNvYJ2kALJ4VQsoUmtgyCR/RBlhETp2jShHobx13pKRaZD7sNzG\n" +
                "UFQI3397oWHy2tRCgJy8/hnj7usxIvCql2Ba6wARAQAB/gkDCG7+FhgkNDgq\n" +
                "YMyvahkvVa5/XMgEuBQ+mGmSkgm1RWJHVlbTLsLB5DNXoO/J0Lt8K6YieoOL\n" +
                "isKXxguHlSs/VJaB2Ywt9rK89yYMQIUgRLVtUW3aZnbs/2q8tnZC4XjmaRHc\n" +
                "MCHsYGnA2A+01Rj1eLNkcTVRd54uMINcHWdusGffQ04aescv0yTvNABK/qby\n" +
                "Z68y8YbUMx9aJB2HHaiwz+u6cUyxfZyqbi4SS9R/fZKdc08QY1KXUhdW36Ug\n" +
                "SaGhFaBDq03VaQLSmRqZSYy86p1ZQZaTSrv0eM3SwhWncM/JEZSkZ1dz2OuC\n" +
                "umAwH/0Kaxav/HSe7DdFSp5nfQLgxE/fIGYh+s4Vd/OjIDV0mxeVI+jyLV9v\n" +
                "rqMpei1qVNsxWoxqCW8/PG9GdjJZtE2npFZLvaP7tDIT9ob37SSfihSUFuSW\n" +
                "1dDkAjCwRAoXUTYLcAZNVGZGFVA99U64J56/5islRlDDsguZ7ngeTICjgYIu\n" +
                "ldQfve54/p8/MahO5nzmC+1end84As5piIt6fn2CVIrtDmJBSx+mReR/28bB\n" +
                "luXHW3jX3rMrU0zm7jYy0YKzsFHJcMuZ6hHuw6p0exqZyyZkrDWRITInppag\n" +
                "QA8ja8G2bbb39Pjne44VyCqEOEzMgp2sT2hETYxf6WMLzWgMRUhdieACKQ9p\n" +
                "lcnas5/2aBZSCEzZtAH7YEhsSpfDWp5t5ZffViOHWKgxK4Oc9R2fimZjiXGP\n" +
                "it7o+Azn1Qyrb6t1gN6NAm0+Pp+M2CAHXX6UFJBwpJiq9rtl8RObHs+gVkYA\n" +
                "Z9MfAnCrqW+0MszMvDToCbnJVBHw4f4lLvxRhHvKylaLMNdj+GkHkHXc/nM6\n" +
                "X8ZjGRtx2+Y/RQ6I/cRg6WCvnuK3ldyMcA1J/mG4MktOY+kwGECZ7xagk5ji\n" +
                "hcW3a0YFfcKwgMLAXwQYAQgAEwUCW3pg0wkQ4IvmQBYaqBMCGwwAANIsB/4q\n" +
                "fgAQVImS50ma94WICTruf/q2hHI1yu7rGYolm/pRmYJsNJUVVBzQTlxn3YuL\n" +
                "6yBAIcCpLZUZEA86AjPX7rmH+FBDeAWAueLJC/x0LGBnboSeFPKeruTfHjjo\n" +
                "UwcU0BxzlzbilYRTHNT0hGF3JpehvHBKzt/HWaiKVTwv92hs/BfQEt1xC0P+\n" +
                "uRvZyDYYEhYOQPmkILB/SBTp01AOFyxR/E8YKbj7QDDtSK2jShqdO7z3JO77\n" +
                "mJ/ofyJ6IWY+6QF79pYoZaWVoibmRl1scHIvAA7ZZ+KmAjB+sIbo1AlFiTle\n" +
                "uE2dudy5IzdikG8MsFDXNrwPUyFdh6J9nIbq5qUM\n" +
                "=bJ3g\n" +
                "-----END PGP PRIVATE KEY BLOCK-----";
        try {
            outputStream = openFileOutput("secret_alice.dat", Context.MODE_PRIVATE);
            outputStream.write(content.getBytes());
            outputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        content = "" +
                "-----BEGIN PGP MESSAGE-----\n" +
                "Version: OpenPGP.js v2.6.2\n" +
                "Comment: https://openpgpjs.org\n" +
                "\n" +
                "wcBMA+q4FoQMGsVLAQf9FSf4fLpEbEVqd0/vqY/+BShw2js0fK6Cxd7ZE3cb\n" +
                "tHzQD44EGm6pKqdPtiDmXFQqU9Ck+3b6lC/8wq+afKTDu35BevzoVwadu8aY\n" +
                "MkP0wkXMWhbdn4cv1KnNv433OQoMMAF6vq5RoWJD8P+WQhA/ZwcMXhTKcNkg\n" +
                "qUoMdQvJJHbPI+nJTX9iaw5wx4wTiKO69urqi80Rvn8NOZE/JuWixHRa4MQs\n" +
                "m+1T3frV3n/JL4mDk8FKvFROkuryKW/nw/tW7nRW3Z+jCVZBUZ/FlNWyn12E\n" +
                "xYw1yVBNFNGYO1qk4Y4Be78/QGpvXE7T5hKGZ95baUDxY/q6eF5JfDUBvTCR\n" +
                "JNLAugEgaMUUUPSIVWku53dmY3+orfUMbsDl5ScSxGn09NT04o4aqViTRQWw\n" +
                "fJ461xf+j3ssp/GxGE9y/dMcL0RbWX70CAtG9e/EF6C+XGP0N+ijRoLsszKn\n" +
                "LtIZS7F1qo7jSB05OEiIvWZGMwahfg8ziENtiypOm9KSS94NZtkq1dYKmSUH\n" +
                "Kn6hNm/v8M0LiNOY1GbirjxUW+iQUPSuWTEgXJeItR9lbeUNBfupmMFPmxBA\n" +
                "fnBHr79fDypdFxtmVM0tCi0ac32W0uNAvLgyOIe0pg420vWilErTY4iLkZms\n" +
                "267YEtzENE6xYhGYlu++KJPwuqoVENvchpM3dpIyj7gbuRqiuZhIEMNVq5G9\n" +
                "hiTX+ubY6bBpEEukVsQkx0bo53SojhToSWp3ohu8NsEv23PAW3kxcnRiYpHv\n" +
                "dS6e3nM/VPGd47x2IXVNt6GMbJV9cjx9/URsQs1Ew961Ly/WtbK3Grpe4XhK\n" +
                "R0yZqXc/BxsGG2zIfxErzwa/5uWT2Q==\n" +
                "=ZTni\n" +
                "-----END PGP MESSAGE-----";
        try {
            outputStream = openFileOutput("cypher-text.dat", Context.MODE_PRIVATE);
            outputStream.write(content.getBytes());
            outputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void genKeyPairClick(View view) {
        try {
            genKeyPair();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void encryptClick(View view) {
        try {
            encrypt();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        }
    }

    public void decryptClick(View view) {
        try {
            decrypt();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void signAndVerifyClick(View view) {
        try {
            signAndVerify();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * @see "https://github.com/damico/OpenPgp-BounceCastle-Example/blob/master/src/org/jdamico/bc/openpgp/tests/TestBCOpenPGP.java"
     */
    private void genKeyPair() throws IOException, PGPException, NoSuchAlgorithmException {

        RSAKeyPairGenerator rkpg = new RSAKeyPairGenerator();

        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());

        kpg.initialize(2048);

        KeyPair kp = kpg.generateKeyPair();

        FileOutputStream out1 = openFileOutput(privKeyFile, Context.MODE_PRIVATE);
        FileOutputStream out2 = openFileOutput(pubKeyFile, Context.MODE_PRIVATE);

        rkpg.exportKeyPair(out1, out2, kp.getPublic(), kp.getPrivate(), id, passwd.toCharArray(), isArmored);


    }

    /**
     * @see "https://github.com/damico/OpenPgp-BounceCastle-Example/blob/master/src/org/jdamico/bc/openpgp/tests/TestBCOpenPGP.java"
     */
    private void encrypt() throws IOException, PGPException{
//        FileInputStream pubKeyIs = openFileInput("pub_alice.dat");
        FileInputStream pubKeyIs = openFileInput(pubKeyFile);
        FileOutputStream cipheredFileIs = openFileOutput(cipherTextFile, Context.MODE_PRIVATE);
        PgpHelper.getInstance().encryptFile(cipheredFileIs, getFilesDir().getAbsolutePath() + "/" + plainTextFile, PgpHelper.getInstance().readPublicKey(pubKeyIs), isArmored, integrityCheck);
        cipheredFileIs.close();
        pubKeyIs.close();
    }

    /**
     * @see "https://github.com/damico/OpenPgp-BounceCastle-Example/blob/master/src/org/jdamico/bc/openpgp/tests/TestBCOpenPGP.java"
     */
    private void decrypt() throws Exception{
        FileInputStream cipheredFileIs = openFileInput(cipherTextFile);
        FileInputStream privKeyIn = openFileInput(privKeyFile);
        FileOutputStream plainTextFileIs = openFileOutput(decPlainTextFile, Context.MODE_PRIVATE);
        PgpHelper.getInstance().decryptFile(cipheredFileIs, plainTextFileIs, privKeyIn, passwd.toCharArray());
        cipheredFileIs.close();
        plainTextFileIs.close();
        privKeyIn.close();
    }

    /**
     * @see "https://github.com/damico/OpenPgp-BounceCastle-Example/blob/master/src/org/jdamico/bc/openpgp/tests/TestBCOpenPGP.java"
     */
    private void signAndVerify() throws Exception{
        FileInputStream privKeyIn = openFileInput(privKeyFile);
        FileInputStream pubKeyIs = openFileInput(pubKeyFile);
        FileInputStream plainTextInput = openFileInput(plainTextFile);
        FileOutputStream signatureOut = openFileOutput(signatureFile, Context.MODE_PRIVATE);

        byte[] bIn = PgpHelper.getInstance().inputStreamToByteArray(plainTextInput);
        byte[] sig = PgpHelper.getInstance().createSignature(getFilesDir().getAbsolutePath() + "/" + plainTextFile, privKeyIn, signatureOut, passwd.toCharArray(), true);
        PgpHelper.getInstance().verifySignature(getFilesDir().getAbsolutePath() + "/" + plainTextFile, sig, pubKeyIs);
    }
}

