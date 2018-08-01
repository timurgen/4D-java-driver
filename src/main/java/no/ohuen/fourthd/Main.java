package no.ohuen.fourthd;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author 100tsa
 */
public class Main {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, KeyManagementException {
        FOURD cnx = FOURD.init();
        cnx.fourd_connect("host", "user", "pass", 19812);
    }
}
