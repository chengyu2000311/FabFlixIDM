package edu.uci.ics.hcheng10.service.idm.core;

import edu.uci.ics.hcheng10.service.idm.IDMService;
import edu.uci.ics.hcheng10.service.idm.logger.ServiceLogger;
import edu.uci.ics.hcheng10.service.idm.security.Crypto;
import edu.uci.ics.hcheng10.service.idm.security.Session;
import org.apache.commons.codec.Decoder;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.glassfish.jersey.message.internal.StringHeaderProvider;

import javax.annotation.Nullable;
import java.sql.*;

public class RegisterInfo {

    public static boolean checkEmailExist(String email) {
        try {
            // Construct the query
            String query =  "SELECT email" +
                    " FROM user" +
                    " WHERE email LIKE ?;";

            // Create the prepared statement
            PreparedStatement ps = IDMService.getCon().prepareStatement(query);

            // Set the arguments
            ps.setString(1, email);

            // Save the query result to a ResultSet so records may be retrieved
            ServiceLogger.LOGGER.info("Trying query: " + ps.toString());
            ResultSet rs = ps.executeQuery();
            // Use executeQuery() for queries that RETRIEVE from DB (returns ResultSet)
            // Use executeUpdate() for queries that CHANGE the DB (returns # of rows modified as int)
            // Use execute() for general purpose queries
            ServiceLogger.LOGGER.info("Query succeeded.");

            // Retrieve the students from the Result Set
            // ResultSets are like iterators (they start from BEFORE the first result)
            while (rs.next()) {
                String theEmail = rs.getString("email");
                ServiceLogger.LOGGER.info("Retrieved student: ("  + theEmail+" )");
                if (theEmail.equals(email)) return true;
            }

        } catch (SQLException e) {
            ServiceLogger.LOGGER.warning("Query failed: Unable to retrieve student records.");
            e.printStackTrace();
        }
        return false;
    }

    public static int authCheck(String email, char[] password) {
        try {
            // Construct the query
            String query =  "SELECT user_id, email, salt, pword" +
                    " FROM user" +
                    " WHERE email LIKE ?;";

            // Create the prepared statement
            PreparedStatement ps = IDMService.getCon().prepareStatement(query);

            // Set the arguments
            ps.setString(1, email);

            // Save the query result to a ResultSet so records may be retrieved
            ServiceLogger.LOGGER.info("Trying query: " + ps.toString());
            ResultSet rs = ps.executeQuery();
            // Use executeQuery() for queries that RETRIEVE from DB (returns ResultSet)
            // Use executeUpdate() for queries that CHANGE the DB (returns # of rows modified as int)
            // Use execute() for general purpose queries
            ServiceLogger.LOGGER.info("Query succeeded.");

            // Retrieve the students from the Result Set
            // ResultSets are like iterators (they start from BEFORE the first result)
            while (rs.next()) {
                Integer user_id = rs.getInt("user_id");
                String theEmail = rs.getString("email");
                String thePassword = rs.getString("pword");
                String theSalt = rs.getString("salt");
                ServiceLogger.LOGGER.info("Retrieved student: (" + user_id + "," + theEmail+" )");
                byte[] decodedSalt = Hex.decodeHex(theSalt);
                byte[] hashedPassword = Crypto.hashPassword(password, decodedSalt, Crypto.ITERATIONS, Crypto.KEY_LENGTH);
                String p = Hex.encodeHexString(hashedPassword); // decode password
                if (p.equals(thePassword)) return 120;
                else return 11;
            }

        } catch (DecoderException d) {
            ServiceLogger.LOGGER.warning("Decode password failed: Unable to decode password");
            d.printStackTrace();
        } catch (SQLException e) {
            ServiceLogger.LOGGER.warning("Query failed: Unable to retrieve student records.");
            e.printStackTrace();
        }
        return 14; // rs.next() is false at the first place
    }

    public static void updateSession(Timestamp lastUsed, Timestamp exprTime, Timestamp timeCreated, String email) {
        try {
            String query =  "UPDATE session " +
                            "SET session.status = ?, session.last_used = ?, session.expr_time = ?, session.time_created = ? " +
                            "WHERE session.email LIKE ?;";
            PreparedStatement ps1 = IDMService.getCon().prepareStatement(query);

            ps1.executeUpdate("SET FOREIGN_KEY_CHECKS=0");
            ps1.setInt(1, 3);
            ps1.setTimestamp(2, lastUsed);
            ps1.setTimestamp(3, exprTime);
            ps1.setTimestamp(4, timeCreated);
            ps1.setString(5, email);
            ServiceLogger.LOGGER.warning("Update: "+ps1.toString());
            ps1.executeUpdate();
        } catch(SQLException e) {
            ServiceLogger.LOGGER.warning("Query failed: Unable to retrieve student records.");
            e.printStackTrace();
        }
    }

    public static int getPlevel(String email) {
        int plevel = 0;
        try {
            String query = "SELECT plevel " +
                        "FROM user " +
                        "WHERE email LIKE ?";
            PreparedStatement ps = IDMService.getCon().prepareStatement(query);
            ps.setString(1, email);
            ServiceLogger.LOGGER.info("Query : " + ps.toString());
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                return rs.getInt(1);
            }
            return plevel;
        } catch (SQLException e) {
            ServiceLogger.LOGGER.warning("Query failed: Unable to retrieve student records.");
            e.printStackTrace();
        }
        return plevel;
    }
    public static String loginSessionCheck(String email, @Nullable Session newSession) {
        String Sid = "";
        try {
            // Construct the query
//            String query1 = "UPDATE session\n" +
//                    "SET session.status = 3\n" +
//                    "WHERE session.expr_time < ?;";

            String query2 = "SELECT SS.status, S.session_id\n" +
                    "FROM session S INNER JOIN session_status SS ON S.status=SS.status_id\n" +
                    "WHERE S.email LIKE ?";
            // Create the prepared statement
//            PreparedStatement ps1 = IDMService.getCon().prepareStatement(query1);
            PreparedStatement ps2 = IDMService.getCon().prepareStatement(query2);
//            ps1.setTimestamp(1,new Timestamp(System.currentTimeMillis()));
//            ps1.executeUpdate();
            ps2.setString(1, email);
            ResultSet rs = ps2.executeQuery();
            // Set the arguments
            // Save the query result to a ResultSet so records may be retrieved
//            ServiceLogger.LOGGER.info("Trying query: " + ps1.toString());
            ServiceLogger.LOGGER.info("Trying query: " + ps2.toString());
            // Use executeQuery() for queries that RETRIEVE from DB (returns ResultSet)
            // Use executeUpdate() for queries that CHANGE the DB (returns # of rows modified as int)
            // Use execute() for general purpose queries
            ServiceLogger.LOGGER.info("Query succeeded.");

            // Retrieve the students from the Result Set
            // ResultSets are like iterators (they start from BEFORE the first result)
            while (rs.next()) {
                String status = rs.getString(1);
                Sid = rs.getString(2);
                if (status.equals("Active") || status.equals("Revokded")) {
                    newSession = Session.rebuildSession(email, newSession.getSessionID(),newSession.getTimeCreated(),
                            newSession.getLastUsed(), newSession.getExprTime());
                    RegisterInfo.updateSession(newSession.getLastUsed(), newSession.getExprTime(), newSession.getTimeCreated(), email);
                    return Sid;
                } else {
//                    String query3 =  "INSERT INTO session_status (status_id, status)" +
//                                     " VALUES (?, ?);";
                    String query4 =  "INSERT INTO session (session_id, email, status, time_created, last_used, expr_time)" +
                                     " VALUES (?, ?, ?, ?, ?, ?);";
//                    PreparedStatement ps3 = IDMService.getCon().prepareStatement(query3);
                    PreparedStatement ps4 = IDMService.getCon().prepareStatement(query4);
//                    ps3.setInt(1, newSession.getSessionID().hashCode());
//                    ps3.setString(2, "Active");
                    ps4.setString(1, newSession.getSessionID().toString());
                    ps4.setString(2, email);
                    ps4.setInt(3, 1);
                    ps4.setTimestamp(4, newSession.getTimeCreated());
                    ps4.setTimestamp(5, newSession.getLastUsed());
                    ps4.setTimestamp(6, newSession.getExprTime());
                    ServiceLogger.LOGGER.info("Trying query: " + ps4.toString());
                    ps4.executeUpdate();
                    ServiceLogger.LOGGER.info("Inserting sucessfully: ");
                }
                return Sid;
            }
            String query4 =  "INSERT INTO session (session_id, email, status, time_created, last_used, expr_time)" +
                    " VALUES (?, ?, ?, ?, ?, ?);";
//                    PreparedStatement ps3 = IDMService.getCon().prepareStatement(query3);
            PreparedStatement ps4 = IDMService.getCon().prepareStatement(query4);
//                    ps3.setInt(1, newSession.getSessionID().hashCode());
//                    ps3.setString(2, "Active");
            ps4.setString(1, newSession.getSessionID().toString());
            ps4.setString(2, email);
            ps4.setInt(3, 1);
            ps4.setTimestamp(4, newSession.getTimeCreated());
            ps4.setTimestamp(5, newSession.getLastUsed());
            ps4.setTimestamp(6, newSession.getExprTime());
            ServiceLogger.LOGGER.info("Trying query: " + ps4.toString());
            ps4.executeUpdate();
            ServiceLogger.LOGGER.info("Inserting sucessfully: ");
            return Sid;
        } catch (SQLException e) {
            ServiceLogger.LOGGER.warning("Query failed: Unable to retrieve student records.");
            e.printStackTrace();
        }
        return Sid; // rs.next() is false at the first place
    }
}
