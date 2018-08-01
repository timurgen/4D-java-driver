package no.ohuen.fourthd;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author 100tsa
 */
public class Communications {

    private final int HEADER_GROW_SIZE = 1024;

    int socket_send(FOURD cnx, String message) {
        PrintWriter out;
        try {
            out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(cnx.socket.getOutputStream())));
            out.println(message);
            out.flush();
        } catch (IOException ex) {
            Logger.getLogger(Communications.class.getName()).log(Level.SEVERE, null, ex);
            return 1;
        }
        return 0;
    }

    int socket_receiv_header(FOURD cnx, FOURD_RESULT state) throws IOException {
        long iResult = 0;
        int offset = 0;
        int len = 0;
        boolean crlf = false;
        int grow_size = HEADER_GROW_SIZE;
        int new_size = grow_size;

        //allocate some space to start with
        state.header = new StringBuilder();

        InputStreamReader socketReader = new InputStreamReader(cnx.socket.getInputStream());

        //read the HEADER only
        do {
            offset += 1;

            iResult = socketReader.read();
            state.header.append((char) iResult);
            len += 1;
            if (len > new_size - 5) {
                //header storage nearly full. Allocate more.
                new_size = new_size + grow_size;
                state.header.ensureCapacity(new_size);
            }
            if (len > 3) {
                if (state.header.charAt(offset - 4) == '\r'
                        && state.header.charAt(offset - 3) == '\n'
                        && state.header.charAt(offset - 2) == '\r'
                        && state.header.charAt(offset-1) == '\n') {
                    crlf = true;
                }
            }

        } while (iResult != -1 && !crlf);

        if (!crlf) {

            System.err.println("Error: Header-end not found");

            return 1;
        }
        state.headerSize = len;

        System.out.println(String.format("Receive:\n%s", state.header));

        //there we must add reading data
        //before analyse header 
        //see COLUMN-TYPES section
        return 0;
    }
}
