package sg.gov.ica.test;

import java.io.BufferedInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Scanner;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.Map.Entry;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.math3.stat.descriptive.DescriptiveStatistics;

import com.mitchtalmadge.asciidata.graph.ASCIIGraph;
import com.mitchtalmadge.asciidata.table.ASCIITable;

public class HttpsInjector {

    private static final Random RANDOM = new Random();

    /**
     * Main class.
     * @param args
     */
    public static void main(String[] args) {

        Logger logger = Logger.getLogger(HttpsInjector.class.getName());
        String optService = "service";
        String optPayload = "payload";
        String optSleepTime = "waittime";
        String optThreads = "threads";
        String optDuration = "duration";
        String optHeaders = "headers";

        // Main inputs to send.
        URI service = null;
        Path jsonFile = null;
        int sleepTime = 0;
        int threadCount = 0;
        float maxDuration = 0.0f;
        HashMap<String,String> headers = new HashMap<>();
        TreeMap<Integer, ThreadRecord> results = new TreeMap<>();

        // Define CLI options to accept.
        Options options = new Options();
        options.addOption(new Option("s", optService, true,
            "Required Service endpoint to be targeted."));
        options.addOption(new Option("p", optPayload, true,
            "Required Path of JSON File to be sent as payload."));
        options.addOption(new Option("w", optSleepTime, true, 
            "Optional wait time in Seconds per thread between payload injection. Default is 5 seconds."));
        options.addOption(new Option("t", optThreads, true, 
            "Optional number of threads to fire. Default is 1."));
        options.addOption(new Option("d", optDuration, true, 
            "Optional maximum Duration in Hours for testing. Default is 1."));
        options.addOption(new Option("h", optHeaders, true,
            "Optional Key-Value file name of HTTP Headers to use on every Request."));

        // A block of unnecessary quotes :-)
        String[] quotes = {
            "'I have a dream' - Martin Luther King Jr.",
            "'The only way to do great work is to love what you do' - Steve Jobs",
            "'It does not matter how slowly you go as long as you do not stop' - Confucius",
            "'The greatest glory in living lies not in never falling, but in rising every time we fall' - Nelson Mandela",
            "'Life is not measured by the number of breaths we take, but by the moments that take our breath away' - Maya Angelou",
            "'Be the change you wish to see in the world' - Mahatma Gandhi",
            "'With great power comes great responsibility' - Spiderman's Uncle Ben",
            "'Believe in yourself and all that you are. Know that there is something inside you that is greater than any obstacle' - Christian D. Larson",
            "'The world breaks everyone, and afterward, some are strong at the broken places' - Ernest Hemingway",
            "'The best and most beautiful things in the world cannot be seen or even touched - they must be felt with the heart' - Helen Keller"
        };

        // Parsing the command line inputs.
        CommandLineParser parser = new DefaultParser();
        CommandLine cli = null;
        try {
            cli = parser.parse(options, args);
            sleepTime = Integer.parseInt(cli.getOptionValue(optSleepTime, "5"));
            threadCount = Integer.parseInt(cli.getOptionValue(optThreads, "1"));
            if(!cli.hasOption(optService)) {
                printExampleHelp(options, quotes, RANDOM.nextInt(10));
                System.exit(1);
            }
            service = new URI(cli.getOptionValue(optService));
            maxDuration = Float.parseFloat(cli.getOptionValue(optDuration, "1.0"));
            jsonFile = Path.of(cli.getOptionValue(optPayload));
            if(!Files.exists(jsonFile)) {
                logger.severe("File specified does not exist ["+cli.getOptionValue(optPayload)+"]");
                System.exit(1);
            }
            if(cli.hasOption(optHeaders)) {
                Path headersFile = Path.of(cli.getOptionValue(optHeaders));
                if(!Files.exists(headersFile)) {
                    logger.severe("HTTP Headers File specified does not exist ["+cli.getOptionValue(optHeaders)+"]");
                    System.exit(1);
                }
                Scanner fileScanner = new Scanner(new BufferedInputStream(new FileInputStream(headersFile.toFile())));
                while(fileScanner.hasNextLine()) {
                    String[] lineTokens = fileScanner.nextLine().trim().split("\\s", 2);
                    headers.put(lineTokens[0].trim(), lineTokens[1].trim());
                }
                fileScanner.close();
            }
        } catch (ParseException pe) {
            logger.severe("Parsing failed.  Reason: " + pe.getMessage());
            printExampleHelp(options, quotes, RANDOM.nextInt(10));
            System.exit(1);
        } catch (URISyntaxException urise) {
            logger.severe("Invalid Service endpoint specified.  Reason: " + urise.getMessage());
            System.exit(1);
        } catch (FileNotFoundException e) {
            logger.severe("File parsing failed.  Reason: " + e.getMessage());
            System.exit(1);
        }

        if(logger.isLoggable(Level.INFO)) {
            logger.info("Starting Execution.");
        }

        // Build thread pool.
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        HttpsInjector httpsInjector = new HttpsInjector();
        for(int i = 1; i<=threadCount; i++) {
            try {
                HttpsInjector.RunThread worker = httpsInjector.createRunThread(i, service, jsonFile, sleepTime, maxDuration, headers, results);
                if(logger.isLoggable(Level.INFO)) {
                    logger.info("Spawn thread "+i);
                }
                executor.execute(worker);
                if(logger.isLoggable(Level.INFO)) {
                    logger.info("Started thread "+i);
                }
            } catch (IOException e) {
                logger.log(Level.SEVERE, e.getMessage(), e);
            }
        }

        // Shutdown thread pool once all is done.
        executor.shutdown();
        // Wait for threads to finish.
        while (!executor.isTerminated());

        if(logger.isLoggable(Level.INFO)) {
            logger.info("Completed execution");
        }

        // Collecting Statistics
        String[][] tableCells = new String[threadCount][3];
        ArrayList<Double> combined90 = new ArrayList<>();
        ArrayList<Double> combined95 = new ArrayList<>();
        ArrayList<Double> combinedAll = new ArrayList<>();
        for(Entry<Integer, ThreadRecord> entry : results.entrySet()) {
            int index = entry.getKey() -1;
            tableCells[index][0] = String.valueOf(entry.getKey());
            combinedAll.addAll(entry.getValue().getResponses());
            DescriptiveStatistics stats = new DescriptiveStatistics(entry.getValue().getResponses().stream().mapToDouble(Number::doubleValue).toArray());
            double percentile90 = stats.getPercentile(90);
            double percentile95 = stats.getPercentile(95);
            combined90.add(percentile90);
            combined95.add(percentile95);
            tableCells[index][1] = String.valueOf(percentile90);
            tableCells[index][2] = String.valueOf(percentile95);
        }

        // Printing Graph
        double[] toPlot = combined90.stream().mapToDouble(Number::doubleValue).toArray();
        if(logger.isLoggable(Level.INFO)) {
            logger.info("\n90th Percentile Response across Threads\n"+ASCIIGraph.fromSeries(toPlot).plot());
        }
        toPlot = combined95.stream().mapToDouble(Number::doubleValue).toArray();
        if(logger.isLoggable(Level.INFO)) {
            logger.info("\n95th Percentile Response across Threads\n"+ASCIIGraph.fromSeries(toPlot).plot());
        }

        // Printing Table
        String[] tableHeader = new String[]{"Thread-ID", "90%-tile (ms)", "95%-tile (ms)"};
        if(logger.isLoggable(Level.INFO)) {
            logger.info("\nStatistics of each thread\n"+ASCIITable.fromData(tableHeader, tableCells).toString());
        }

        tableHeader = new String[]{"Overall", "90%-tile (ms)", "95%-tile (ms)"};
        DescriptiveStatistics overallStats = new DescriptiveStatistics(combinedAll.stream().mapToDouble(Number::doubleValue).toArray());
        tableCells = new String[][] {
            {
                "Overall", 
                String.valueOf(overallStats.getPercentile(90)), 
                String.valueOf(overallStats.getPercentile(95)) 
            }
        };
        if(logger.isLoggable(Level.INFO)) {
            logger.info("\nOverall Statistics\n"+ASCIITable.fromData(tableHeader, tableCells).toString());
        }

    }

    private static void printExampleHelp(Options options, String[] quotes, int messageId) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp(
            110, 
            "httpsloadinjector -p <JSON-FILE> -s <HTTPS-URL> [options]", 
            "=============================================================================================================\n"
                + "Required and Optional inputs."
                + "\n-------------------------------------------------------------------------------------------------------------", 
            options,
            "-------------------------------------------------------------------------------------------------------------\n" 
                + quotes[messageId] 
                + "\n=============================================================================================================");
    }

    public RunThread createRunThread(int threadId, URI serviceUri, Path jsonFile, int sleepSeconds, float maxDurationHour, Map<String,String> headers, SortedMap<Integer, ThreadRecord> results) throws IOException {
        return new RunThread(threadId, serviceUri, jsonFile, sleepSeconds, maxDurationHour, headers, results);
    }

    /**
     * This is a stub implementation that will accept the same hostname as the specified Service Endpoint.
     * Not for Production use.
     */
    private class HostnameVerifierImpl implements HostnameVerifier {

        private String targetHostname = null;

        public HostnameVerifierImpl(String targetHostname) {
            this.targetHostname = targetHostname;
        }

        @Override
        public boolean verify(String hostname, SSLSession session) {
            return this.targetHostname.equalsIgnoreCase(hostname);
        }
        
    }

    /**
     * This is the Runnable thread class.
     */
    private class RunThread implements Runnable {

        private URI serviceURI = null;
        private String jsonString = null;
        private int sleepSeconds = 0;
        private float maxDurationHour = 0.0f;
        private int threadId = 0;
        private Map<String,String> headers = null;
        private SortedMap<Integer, ThreadRecord> results;

        private  Logger logger = Logger.getLogger(RunThread.class.getName());
        private Random random = new Random();
        private TrustManager[] trustAllCerts;

        private long startTime = (new Date()).getTime();

        public RunThread(int threadId, URI serviceUri, Path jsonFile, int sleepSeconds, float maxDurationHour, Map<String,String> headers, SortedMap<Integer, ThreadRecord> results) throws IOException {
            this.threadId = threadId;
            this.serviceURI = serviceUri;
            this.jsonString = Files.readString(jsonFile);
            this.sleepSeconds = sleepSeconds;
            this.maxDurationHour = maxDurationHour;
            this.headers = headers;
            this.results = results;

            trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        if(logger.isLoggable(Level.FINEST)) {
                            logger.finest("Do nothing to bypass certificate validation.");
                        }
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        if(logger.isLoggable(Level.FINEST)) {
                            logger.finest("Do nothing to bypass certificate validation.");
                        }
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
            };
        }

        public void run() {

            long runDuration = Math.round(this.maxDurationHour * 1000l * 60l * 60l);
            boolean stop = false;

            ThreadRecord threadRecord = new ThreadRecord(this.threadId);

            SSLContext sc = null;
            try {
                sc = SSLContext.getInstance("TLSv1.2");
                sc.init(null, trustAllCerts, new java.security.SecureRandom());
            } catch (NoSuchAlgorithmException e) {
                logger.log(Level.SEVERE, e.getMessage(), e);
                System.exit(1);
            } catch (KeyManagementException e) {
                logger.log(Level.SEVERE, e.getMessage(), e);
            }
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            // Create all-trusting host name verifier
            HostnameVerifier validHosts = new HostnameVerifierImpl(this.serviceURI.getHost());
            // All hosts will be valid
            HttpsURLConnection.setDefaultHostnameVerifier(validHosts);

            if(logger.isLoggable(Level.INFO)) {
                logger.info("Starting Thread ["+this.threadId+"]");
            }

            // Iterate until end.
            while(true) {
                // Check if it is time to end.
                long currentTime = (new Date()).getTime();
                if(stop || ((startTime + runDuration) < currentTime) ) {
                    if(logger.isLoggable(Level.INFO)) {
                        logger.info("Stopping Thread ["+this.threadId+"]");
                    }
                    break; // end the running thread.
                }

                // Send HTTPS connection.
                try {
                    StringBuilder logStmt = new StringBuilder();
                    logStmt.append("Thread [").append(this.threadId).append("] sending");
                    if(logger.isLoggable(Level.INFO)) {
                        logger.info(logStmt.toString());
                    }
                    HttpsURLConnection httpsConnection = (HttpsURLConnection) this.serviceURI.toURL().openConnection();
                    // add request header
                    httpsConnection.setRequestMethod("POST");
                    httpsConnection.setRequestProperty("Accept-Language", "en-US,en;q=0.5");
                    httpsConnection.setRequestProperty("Content-Type", "application/json");
                    for(Map.Entry<String,String> entry : this.headers.entrySet()) {
                        httpsConnection.setRequestProperty(entry.getKey(), entry.getValue());
                    }

                    // Send post request
                    httpsConnection.setDoOutput(true);
                    DataOutputStream wr = new DataOutputStream(httpsConnection.getOutputStream());
                    wr.writeBytes(this.jsonString);
                    wr.flush();
                    wr.close();

                    int responseCode = httpsConnection.getResponseCode();

                    long newTime = (new Date()).getTime();
                    logStmt = new StringBuilder();
                    long elapsedTime = newTime-currentTime;
                    threadRecord.addResponse(elapsedTime);
                    logStmt.append("Thread [").append(this.threadId).append("] response code [").append(responseCode).append("] Elapsed [").append(elapsedTime).append("]ms.");
                    if(logger.isLoggable(Level.INFO)) {
                        logger.info(logStmt.toString());
                    }

                    // Put thread to sleep.
                    Thread.sleep(this.sleepSeconds * 1000l + random.nextInt(1000)); // Change from nextLong(bound) to nextInt(bound) to support Java 11.

                } catch (IOException e) {
                    logger.log(Level.SEVERE, e.getMessage(), e);
                    stop = true; // Do not continue if there is exception.
                } catch (InterruptedException e) {
                    logger.log(Level.SEVERE, e.getMessage(), e);
                    stop = true;
                    Thread.currentThread().interrupt();
                }
            }

            this.results.put(threadRecord.getThreadId(), threadRecord);

            if(logger.isLoggable(Level.INFO)) {
                logger.info("Ended Thread ["+this.threadId+"]");
            }

        }
    }

    /**
     * To store the runtime records of each Thread.
     */
    private class ThreadRecord {
        private int threadId;
        private ArrayList<Double> responses = new ArrayList<>();

        public ThreadRecord (int threadId) {
            this.threadId = threadId;
        }

        public int getThreadId() {
            return this.threadId;
        }

        public void addResponse(double response) {
            this.responses.add(response);
        }

        public List<Double> getResponses() {
            return this.responses;
        }
    }
}
