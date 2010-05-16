package ru.ifmo.secureinfo.srp;

/**
 * User: danielpenkin
 * Date: May 9, 2010
 */
public interface SRPRecordStorage {

    SRPUserRecord getUserRecord(String username);

}