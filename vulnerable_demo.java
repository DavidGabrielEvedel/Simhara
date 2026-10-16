import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class vulnerable_demo {

    // VULNERABILITY 1: Hardcoded credentials
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "SuperSecret123";

    // VULNERABILITY 2: SQL Injection
    public static void findUser(String username) throws Exception {
        Connection conn = DriverManager.getConnection(
            "jdbc:mysql://localhost:3306/testdb",
            DB_USER,
            DB_PASSWORD
        );

        Statement stmt = conn.createStatement();

        String query = "SELECT * FROM users WHERE username = '"
                     + username + "'";

        ResultSet rs = stmt.executeQuery(query);

        while (rs.next()) {
            System.out.println(rs.getString("username"));
        }

        rs.close();
        stmt.close();
        conn.close();
    }

    // VULNERABILITY 3: Command Injection
    public static void pingHost(String host) throws Exception {
        String command = "ping -c 1 " + host;

        Process process = Runtime.getRuntime().exec(
            new String[]{"sh", "-c", command}
        );

        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );

        String line;

        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }

        reader.close();
    }

    // VULNERABILITY 4: Weak cryptographic hash
    public static String hashPassword(String password)
            throws Exception {
        java.security.MessageDigest md =
            java.security.MessageDigest.getInstance("MD5");

        byte[] hash = md.digest(password.getBytes("UTF-8"));

        StringBuilder result = new StringBuilder();

        for (byte b : hash) {
            result.append(String.format("%02x", b));
        }

        return result.toString();
    }

    // VULNERABILITY 5: Information disclosure
    public static void handleError(Exception e) {
        e.printStackTrace();
    }

    public static void main(String[] args) {
        System.out.println("Simhara Java security test fixture");
    }
}