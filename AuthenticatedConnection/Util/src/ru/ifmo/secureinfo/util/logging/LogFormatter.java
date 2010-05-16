package ru.ifmo.secureinfo.util.logging;

import java.util.Calendar;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;

/**
 * User: danielpenkin
 * Date: May 13, 2010
 */
public class LogFormatter extends Formatter {

    private final Calendar cal = Calendar.getInstance();

    @Override
    public String format(LogRecord record) {
        StringBuilder log = new StringBuilder();
        log.append(record.getThreadID()).append("\t");
        cal.setTimeInMillis(record.getMillis());
        log.append("[").append(record.getLevel()).append("]\t");
        log.append("[").append(cal.getTime().toString()).append("]\t");
        log.append(record.getMessage()).append("\t");
        log.append("<").append(record.getSourceClassName());
        log.append(":").append(record.getSourceMethodName()).append(">\n");

        return log.toString();
    }
}