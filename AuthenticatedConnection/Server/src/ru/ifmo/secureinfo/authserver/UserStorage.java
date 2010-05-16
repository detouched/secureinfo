package ru.ifmo.secureinfo.authserver;

import ru.ifmo.secureinfo.srp.SRPRecordStorage;
import ru.ifmo.secureinfo.srp.SRPUserRecord;
import ru.ifmo.secureinfo.util.coders.HEXCoder;

import java.io.*;
import java.math.BigInteger;
import java.util.Map;
import java.util.TreeMap;

/**
 * User: danielpenkin
 * Date: May 11, 2010
 */
public class UserStorage implements SRPRecordStorage {

    private final Map<String, SRPUserRecord> records = new TreeMap<String, SRPUserRecord>();

    public int loadFromFile(File file, boolean append) throws FileNotFoundException, IOException {
        if (!append) {
            records.clear();
        }

        int count = 0;
        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line;
        while ((line = reader.readLine()) != null) {
            String[] part = line.split(" ");
            if (part.length == 4) {
                String name = part[0];
                byte[] username = HEXCoder.hex2bytes(part[1]);
                byte[] salt = HEXCoder.hex2bytes(part[2]);
                byte[] verifier = HEXCoder.hex2bytes(part[3]);
                SRPUserRecord record = new SRPUserRecord(username,
                        new BigInteger(salt), new BigInteger(verifier));
                synchronized (records) {
                    records.put(name, record);
                    count++;
                }
            }
        }

        reader.close();

        return count;
    }

    public void saveToFile(File file, boolean append) throws IOException {
        synchronized (records) {
            FileWriter writer = new FileWriter(file, append);
            writer.write("\n");
            for (Map.Entry<String, SRPUserRecord> record : records.entrySet()) {
                String name = record.getKey();
                SRPUserRecord rec = record.getValue();
                writer.write(name + " " + HEXCoder.bytes2hex(rec.getUsername()));
                writer.write(" " + HEXCoder.bytes2hex(rec.getSalt().toByteArray()));
                writer.write(" " + HEXCoder.bytes2hex(rec.getVerifier().toByteArray()));
                writer.write("\n");
            }
            writer.close();
        }
    }

    public SRPUserRecord getUserRecord(String username) {
        return records.get(username);
    }

    public SRPUserRecord addUserRecord(String name, SRPUserRecord record) {
        synchronized (records) {
            return records.put(name, record);
        }
    }

    public SRPUserRecord removeUserRecord(String username) {
        synchronized (records) {
            return records.remove(username);
        }
    }

}