package com.sap.cloud.security.cas;

import com.sap.cloud.security.cas.client.ADCException;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * TODO: extract as library
 */
public class ADCExecutor {
    private static ADCExecutor instance = null;
    private static final Logger LOGGER = LoggerFactory.getLogger(ADCExecutor.class);

    private Process adcProcess;

    public static ADCExecutor get() {
        if (instance == null) {
            instance = new ADCExecutor();
        }
        return instance;
    }

    public void start() throws IOException {
        LOGGER.info("start adc process...");
        ProcessBuilder pb = new ProcessBuilder( "/bin/bash", System.getenv("OPA_START") );

        adcProcess = pb.start();

        LOGGER.info("started adc process");

        new Thread(new DumpInputRunnable(adcProcess, adcProcess.getInputStream())).start();
        new Thread(new DumpInputRunnable(adcProcess, adcProcess.getErrorStream())).start();
    }

    public void stop() {
        adcProcess.destroy();
        if (adcProcess.isAlive()) {
            adcProcess = adcProcess.destroyForcibly();
        }
        new Thread(new DumpInputRunnable(adcProcess, adcProcess.getInputStream())).start();
        new Thread(new DumpInputRunnable(adcProcess, adcProcess.getErrorStream())).start();
    }

    public String getVersion() throws InterruptedException, IOException {
        Process process = Runtime.getRuntime().exec("/home/vcap/app/opa version");
        process.waitFor();
        int exitValue = process.exitValue();
        if (exitValue != 0) {
            throw new ADCException(IOUtils.toString(process.getErrorStream(), StandardCharsets.UTF_8));
        }
        return IOUtils.toString(process.getInputStream(), StandardCharsets.UTF_8);
    }

    private class DumpInputRunnable implements Runnable {
        Process process;
        InputStream inputStream;

        DumpInputRunnable(Process p, InputStream is) {
            this.process = p;
            this.inputStream = is;
        }

        @Override
        public void run() {
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            while (process.isAlive()) {
                try {
                    LOGGER.info("Open Policy Agent: {}", reader.readLine());
                } catch (IOException ex) {
                    LOGGER.info("Error when dumping Open Policy Agent logs: ", ex);
                }
            }
        }
    }
}
