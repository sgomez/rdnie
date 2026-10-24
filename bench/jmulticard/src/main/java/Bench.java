import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.dnie.Dnie;
import es.gob.jmulticard.card.dnie.DnieFactory;
import es.gob.jmulticard.crypto.BcCryptoHelper;
import es.gob.jmulticard.jse.provider.CachePasswordCallback;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Properties;

/** JMulticard counterpart of `examples/bench.rs`: same steps, same output, times only. */
public final class Bench {

    private static final String SIGNATURE_LABEL = "CertFirmaDigital";

    public static void main(final String[] args) throws Exception {
        final int runs = Math.max(1, Integer.parseInt(option(args, "--runs", "20")));
        System.out.println("tool: jmulticard " + version());

        final double[] open = new double[runs];
        final double[] certificate = new double[runs];
        final double[] total = new double[runs];
        for (int run = 0; run < runs; run++) {
            final long start = System.nanoTime();
            final SmartcardIoConnection connection = new SmartcardIoConnection();
            final Dnie dnie = DnieFactory.getDnie(connection, null, new BcCryptoHelper(), null);
            final long opened = System.nanoTime();
            if (dnie.getCertificate(SIGNATURE_LABEL) == null) {
                throw new IllegalStateException("no signature certificate");
            }
            final long read = System.nanoTime();
            connection.close();
            open[run] = millis(opened - start);
            certificate[run] = millis(read - opened);
            total[run] = millis(read - start);
        }
        // getDnie lists the labels and reads every certificate, so it covers both rdnie steps.
        summary("connect + open + labels", open);
        summary("certificate (signature)", certificate);
        summary("total", total);

        if (Arrays.asList(args).contains("--sign")) {
            sign();
        }
    }

    /** One signature of fixed data in a fresh session, timed from the secure channel to the result. */
    private static void sign() throws Exception {
        final char[] pin = System.console().readPassword("PIN (not shown): ");
        final SmartcardIoConnection connection = new SmartcardIoConnection();
        final Dnie dnie = DnieFactory.getDnie(
            connection, new CachePasswordCallback(pin), new BcCryptoHelper(), null
        );
        final PrivateKeyReference key = dnie.getPrivateKey(SIGNATURE_LABEL);
        final long start = System.nanoTime();
        dnie.sign("rdnie bench".getBytes(), "SHA256withRSA", key);
        summary("sign", new double[] { millis(System.nanoTime() - start) });
        Arrays.fill(pin, '\0');
        connection.close();
    }

    private static String version() throws IOException {
        final Properties properties = new Properties();
        try (InputStream pom = Dnie.class.getResourceAsStream(
            "/META-INF/maven/es.gob.afirma.jmulticard/jmulticard/pom.properties"
        )) {
            properties.load(pom);
        }
        return properties.getProperty("version");
    }

    private static String option(final String[] args, final String flag, final String fallback) {
        final int index = Arrays.asList(args).indexOf(flag);
        return index >= 0 && index + 1 < args.length ? args[index + 1] : fallback;
    }

    private static double millis(final long nanos) {
        return nanos / 1e6;
    }

    private static void summary(final String step, final double[] times) {
        Arrays.sort(times);
        System.out.printf(
            "%s: median %.1f ms, min %.1f ms, max %.1f ms (%d runs)%n",
            step, times[times.length / 2], times[0], times[times.length - 1], times.length
        );
    }
}
