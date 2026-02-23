package dev.mistial.tests.openfips201;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import com.makina.security.openfips201.OpenFIPS201;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import static org.junit.jupiter.api.Assertions.*;

class OpenFIPS201Test {
    CardSimulator simulator;

    /**
     * AID for the OpenFIPS201 applet
     */
    private static final AID OF201_AID = AIDUtil.create("A000000308000010000100");

    public static byte[] hexStringToByteArray(String s) {
        // Remove spaces
        s = s.replace(" ", "");

        // Ensure the string has an even length
        if (s.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hexadecimal string provided.");
        }

        byte[] bytes = new byte[s.length() / 2];
        for (int i = 0; i < s.length(); i += 2) {
            bytes[i / 2] = (byte) Integer.parseInt(s.substring(i, i + 2), 16);
        }

        return bytes;
    }

    private void initSimulator() {
        simulator = new CardSimulator();
        simulator.installApplet(OF201_AID, OpenFIPS201.class, new byte[0]);
    }

    @BeforeEach
    void setUp() {
        initSimulator();
    }

    /**
     * Test that applet selection works properly
     */
    @org.junit.jupiter.api.Test
    void testSelect() {
        // Check for a success response
        byte[] dataBytes = simulator.selectAppletWithResult(OF201_AID);

        // The last two bytes of the response should be 0x9000.  Verify that.
        assertArrayEquals(new byte[] { (byte)0x90, (byte)0x00 }, new byte[] { dataBytes[dataBytes.length - 2], dataBytes[dataBytes.length - 1] });
    }

    /**
     * Test that the bug in the applet is fixed
     */
    @Tag("slow")
    @org.junit.jupiter.api.Test
    void testAbortedTransactionsSucceed() {
        try (MockedStatic<GPSystem> mocked = Mockito.mockStatic(GPSystem.class)) {
            SecureChannel mockedSecureChannel = Mockito.mock(SecureChannel.class);

            // Mock getSecurityLevel() to return a value that indicates that the card is authenticated, has decryption, and has MAC
            Mockito.when(mockedSecureChannel.getSecurityLevel()).thenReturn((byte) (SecureChannel.AUTHENTICATED | SecureChannel.C_DECRYPTION | SecureChannel.C_MAC));

            // Mock getSecureChannel() to return the mocked SecureChannel
            Mockito.when(GPSystem.getSecureChannel()).thenReturn(mockedSecureChannel);

            // Mock `short processSecurity(APDU apdu)` to return 0 bytes of data.
            Mockito.when(mockedSecureChannel.processSecurity(Mockito.any())).thenReturn((short)0);

            // Mock `short unwrap(byte[] data, short offset, short length)` to return the length (from the third argument)
            Mockito.when(mockedSecureChannel.unwrap(Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyShort())).thenAnswer(new org.mockito.stubbing.Answer<Short>() {
                @Override
                public Short answer(org.mockito.invocation.InvocationOnMock invocation) throws Throwable {
                    return (Short) invocation.getArgument(2);
                }
            });
            // Check for a success response
            byte[] dataBytes = simulator.selectAppletWithResult(OF201_AID);

            // The last two bytes of the response should be 0x9000.  Verify that.
            assertArrayEquals(new byte[]{(byte) 0x90, (byte) 0x00}, new byte[]{dataBytes[dataBytes.length - 2], dataBytes[dataBytes.length - 1]});

            // Define the configuration command in hex
            byte[] configurationCommand = hexStringToByteArray("E4 DB 3F 00 5D 68 5B A0 24 80 01 FF 81 01 00 82 01 00 " +
                    "83 01 00 84 01 06 85 01 08 86 01 06 87 01 05 88 01 00 89 01 04 8A 01 00 8B 01 00 A1 12 80 01 FF 81 " +
                    "01 00 82 01 08 83 01 06 84 01 05 85 01 00 A2 03 80 01 00 A3 03 80 01 00 A4 15 80 01 00 81 01 00 82 " +
                    "01 00 83 01 00 84 01 FF 85 01 00 86 01 00");

            // Execute the configuration command and get the response
            CommandAPDU configurationCommandAPDU = new CommandAPDU(configurationCommand);
            ResponseAPDU configurationResponseAPDU = simulator.transmitCommand(configurationCommandAPDU);

            // Verify that the response is 0x9000
            assertArrayEquals(new byte[]{(byte) 0x90, (byte) 0x00}, configurationResponseAPDU.getBytes());

            // Create the CHUID object
            byte[] createChuidCommand = hexStringToByteArray("E4 DB 3F 00 0D 64 0B 8B 03 5F C1 02 8C 01 7F 8D 01 7F");
            configurationCommandAPDU = new CommandAPDU(createChuidCommand);
            configurationResponseAPDU = simulator.transmitCommand(configurationCommandAPDU);

            // Verify that the response is 0x9000
            assertArrayEquals(new byte[]{(byte) 0x90, (byte) 0x00}, configurationResponseAPDU.getBytes());

            // Create the Card Authentication Key (9e)
            byte[] createCardAuthenticationKeyCommand = hexStringToByteArray("E4 DB 3F 00 14 66 12 8B 01 9E 8C 01 7F 8D 01 7F 8E 01 11 8F 01 04 90 01 10");
            configurationCommandAPDU = new CommandAPDU(createCardAuthenticationKeyCommand);
            configurationResponseAPDU = simulator.transmitCommand(configurationCommandAPDU);

            // Verify that the response is 0x9000
            assertArrayEquals(new byte[]{(byte) 0x90, (byte) 0x00}, configurationResponseAPDU.getBytes());

            // Generate the Card Authentication Key (9e)
            byte[] generateCardAuthenticationKeyCOmmand = hexStringToByteArray("E4 47 00 9E 05 AC 03 80 01 11 00");
            configurationCommandAPDU = new CommandAPDU(generateCardAuthenticationKeyCOmmand);
            configurationResponseAPDU = simulator.transmitCommand(configurationCommandAPDU);

            // Verify that the response ends in 0x9000
            assertArrayEquals(new byte[]{(byte) 0x90, (byte) 0x00}, new byte[]{configurationResponseAPDU.getBytes()[configurationResponseAPDU.getBytes().length - 2], configurationResponseAPDU.getBytes()[configurationResponseAPDU.getBytes().length - 1]});

            String[] golden_piv_chuid = new String[] {
                    "F4DB3FFFC85C035FC102538208633019D13810D828AB6C10C339E5A1685A08C92ADE0A6184E739C3E732043132333434107B13D0E61F6E478EA0AABE0F9AD64A6C350832303332313230323610DB17539147494A32977D7A3843775E8A3E82080E3082080A06092A864886F70D010702A08207FB308207F7020103310F300D06096086480165030402010500300A06086086480165030601A082055530820551308203B9A003020102020A5853CCE2521801412010300D06092A864886F70D01010B05003065310B3009060355",
                    "F4DB3FFFC804061302555331183016060355040A130F552E532E20476F7665726E6D656E7431183016060355040B130F4943414D205465737420436172647331223020060355040313194943414D20546573742043617264205369676E696E67204341301E170D3138303532343030303030305A170D3332313233303233353935395A3063310B300906035504061302555331183016060355040A130F552E532E20476F7665726E6D656E7431183016060355040B130F4943414D20546573742043617264733120301E060355",
                    "F4DB3FFFC8040313174943414D2050495620436F6E74656E74205369676E657230820122300D06092A864886F70D01010105000382010F003082010A0282010100BE61AB8269BA702A4A64054BAA80CD0F95D30931FFBAA960F96F76E327C8C8CC03E3F1F809E981696318725A04B24169F6EAC4940D2A0457F30F2C09A23B4F04EF8E942323C79E895964DB4B1F9F0BA38462960259EBB070DB77F9D0BEFFA5045AC3B8587BD107209A2DA04D3771A66F75EC4B19FF2A9C9440C4CE01373D9EC483C497645BDCEC28DD2DFB7C",
                    "F4DB3FFFC89FC19A621352EF5609FC77FE86F1D4DBFA1D9E9A62045C1FAE55A0B0C2F02D50B3E417BEE4A503EDDE8B9B638720C7C49FA44228F36BB95E07EE897790D16127040313CDAB502152A71DD7FF5225AE0D21D556965E9040533189A2B1916AE83DC96100556326AF0288F62D8A687B7F732CC648770203010001A38201833082017F301D0603551D0E041604147E058845987A5272B61D6006094ED7E1670E6521301F0603551D230418301680140A657668E6A866BB506AB5BB2B0F91D621EEA2D1300E0603551D0F",
                    "F4DB3FFFC80101FF04040302078030560603551D1F044F304D304BA049A0478645687474703A2F2F687474702E61706C2D746573742E636974652E66706B692D6C61622E676F762F63726C732F4943414D54657374436172645369676E696E6743412E63726C30170603551D200410300E300C060A6086480165030201305630160603551D250101FF040C300A060860864801650306073081A306082B06010505070101048196308193305D06082B060105050730028651687474703A2F2F687474702E61706C2D746573742E",
                    "F4DB3FFFC8636974652E66706B692D6C61622E676F762F6169612F6365727473497373756564546F4943414D54657374436172645369676E696E6743412E703763303206082B060105050730018626687474703A2F2F6F6373702E61706C2D746573742E636974652E66706B692D6C61622E676F76300D06092A864886F70D01010B05000382018100A1FB570EC01840F43E95D20356F28AB2A7921818AB8D54D23CC3CF29699F150E0AA59D8BFF9B0C1A0BF893C62DFD9C08457588A0996DE26FB7E957FAAE45582F384AD8C5",
                    "F4DB3FFFC83AD7B596A8C0E54684E50056A3320DCDF3A25A0C24BFCDF866968056D45D636B29C46E927BBE20ADE10A0E546C254103F2A8248F2ABED904AD07BD4DEAD6CB62EEE568FFA983335020A55C3619BF2CDD71ADC5D78F82C2AB3A3A7F46004D0400470AEDB801873EC639DD52E563CBDE74B9ADF84809B88C32E300184D13E47393542F4D3E7513828A31B436227DBB157BD72FC9280A0C283097270470CC8AF9751A1F94780BF1CE9ABA8D761341C3A74844FDC13FB6FD7E7D33DEDBA9A06BBDCF1D9AB0ED416CC5E3",
                    "F4DB3FFFC8F8DC7B4A687D11DFB5892BEFC129DE38C765969BBBB1AD28CE611BE494AC86A50596EEC8DA6DDB6708E7189B508FF09035B26ABAB1278116EFC1180CF3520308A607C5430B098DD4F233592F5DB24C0A5F7B0B320759F2CDBC0BA30B7DCBCC36A9F18CAB8841816A0E44D2716723D2BD35C2B4413182027A3082027602010130733065310B300906035504061302555331183016060355040A130F552E532E20476F7665726E6D656E7431183016060355040B130F4943414D205465737420436172647331223020",
                    "F4DB3FFFC8060355040313194943414D20546573742043617264205369676E696E67204341020A5853CCE2521801412010300D06096086480165030402010500A081DB301706092A864886F70D010903310A06086086480165030601301C06092A864886F70D010905310F170D3138303732333231343833365A302F06092A864886F70D0109043122042024E806AD8D4DEE87E93677CB8E22EE392D2A023DCB1C54822CD35A74D58DA08830710608608648016503060531653063310B30090603550406130255533118301606",
                    "F4DB3FFFC80355040A130F552E532E20476F7665726E6D656E7431183016060355040B130F4943414D20546573742043617264733120301E060355040313174943414D2050495620436F6E74656E74205369676E6572300B06092A864886F70D010101048201002B1EFBEA4EB50758D10EFA9F4E6CAA7E017909D0F67B0D4A1F3F0DCBDAEB39D864CD8C4CE3090014719E4A9832F56593E2096A30E51531F838FAE7C9AFB6A88D4780D73EB7685172788286AACE99912AEDB6948D771258C05A6F2A50F7AB6E0D737B086F4560",
                    "E4DB3FFF9C74A08EED7B11D395F2FC2F13A1E2C0BC151563F6276EFAD512B36F066B4FA716FBC287DCF58076600E234917D7AA13838954E1F820EC8125E95913F7729C015F2AD4BD563A4194ACAC059CE3F572C8CD4566D5BEBDF1A52B7D49F42964DDA02035310200A516F4AB5CF19915CBE83C7234024D7D1442CD89EBDB095C3ECB833C3B9ABAA23D4C6289D233DE4248B772F53AE22EFE12CC8B435520FE00"
            };

            // Loop through all the APDUs to create the object, send them, and verify the response is 0x9000
            for (int i = 0; i < golden_piv_chuid.length; i++) {
                byte[] createObjectCommand = hexStringToByteArray(golden_piv_chuid[i]);
                configurationCommandAPDU = new CommandAPDU(createObjectCommand);
                configurationResponseAPDU = simulator.transmitCommand(configurationCommandAPDU);

                // Verify that the response is 0x9000
                assertArrayEquals(new byte[]{(byte) 0x90, (byte) 0x00}, configurationResponseAPDU.getBytes());
            }

            // Recreate issue #55 by partially requesting the CHUID and not finishing the object retrieval
            byte[] partialChuidRequest = hexStringToByteArray("00CB3FFF055C035FC10238");
            CommandAPDU partialChuidRequestAPDU = new CommandAPDU(partialChuidRequest);
            ResponseAPDU partialChuidRequestResponseAPDU = simulator.transmitCommand(partialChuidRequestAPDU);

            // Verify that the response is 0x61FF by examining the last two bytes
            assertArrayEquals(new byte[]{(byte) 0x61, (byte) 0xFF}, new byte[]{partialChuidRequestResponseAPDU.getBytes()[partialChuidRequestResponseAPDU.getBytes().length - 2], partialChuidRequestResponseAPDU.getBytes()[partialChuidRequestResponseAPDU.getBytes().length - 1]});

            // Perform a 9e sign operation to verify that the card is still in a good state
            byte[] signCommand = hexStringToByteArray("E4 87 11 9E 26 7C 24 82 00 81 20 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 00 ");
            CommandAPDU signCommandAPDU = new CommandAPDU(signCommand);
            ResponseAPDU signResponseAPDU = simulator.transmitCommand(signCommandAPDU);

            // Verify that the last two bytes of the response are 0x9000
            assertArrayEquals(new byte[]{(byte) 0x90, (byte) 0x00}, new byte[]{signResponseAPDU.getBytes()[signResponseAPDU.getBytes().length - 2], signResponseAPDU.getBytes()[signResponseAPDU.getBytes().length - 1]});
        }
    }

    @org.junit.jupiter.api.Test
    void testSecureChannelUsesUnwrappedLengthInPivHandlers() {
        try (MockedStatic<GPSystem> mocked = Mockito.mockStatic(GPSystem.class)) {
            SecureChannel mockedSecureChannel = Mockito.mock(SecureChannel.class);

            Mockito.when(mockedSecureChannel.getSecurityLevel())
                    .thenReturn((byte) (SecureChannel.AUTHENTICATED | SecureChannel.C_DECRYPTION | SecureChannel.C_MAC));
            Mockito.when(GPSystem.getSecureChannel()).thenReturn(mockedSecureChannel);

            // Simulate SCP unwrap shrinking the payload by 4 bytes (wrapped metadata removed).
            Mockito.when(mockedSecureChannel.unwrap(Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyShort()))
                    .thenAnswer(invocation -> (short) (((short) invocation.getArgument(2)) - 4));

            byte[] dataBytes = simulator.selectAppletWithResult(OF201_AID);
            assertArrayEquals(new byte[]{(byte) 0x90, (byte) 0x00}, new byte[]{dataBytes[dataBytes.length - 2], dataBytes[dataBytes.length - 1]});

            byte[] resetRetryCounterWrapped = hexStringToByteArray(
                    "E4 2C 00 80 14 " +
                            "31 32 33 34 35 36 37 38 " + // PUK guess
                            "31 32 33 34 35 36 37 38 " + // New PIN
                            "AA BB CC DD");              // Wrapped overhead

            ResponseAPDU response = simulator.transmitCommand(new CommandAPDU(resetRetryCounterWrapped));

            // Regression guard: if handlers use getIncomingLength(), this returns SW_WRONG_DATA (6A80).
            assertNotEquals(ISO7816.SW_WRONG_DATA, response.getSW());
            Mockito.verify(mockedSecureChannel, Mockito.atLeastOnce())
                    .unwrap(Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyShort());
        }
    }

    @org.junit.jupiter.api.Test
    void testExtendedLengthCommandOverBufferIsRejected() {
        byte[] dataBytes = simulator.selectAppletWithResult(OF201_AID);
        assertArrayEquals(new byte[]{(byte) 0x90, (byte) 0x00}, new byte[]{dataBytes[dataBytes.length - 2], dataBytes[dataBytes.length - 1]});

        byte[] oversizedPayload = new byte[300];
        for (int i = 0; i < oversizedPayload.length; i++) {
            oversizedPayload[i] = (byte) i;
        }

        // RESET RETRY COUNTER with Nc=300 forces receiveAllIncomingData() to reject
        // because APDU buffer cannot hold contiguous CDATA at this size.
        CommandAPDU oversized = new CommandAPDU(0x00, 0x2C, 0x00, 0x80, oversizedPayload, 0);
        ResponseAPDU response = simulator.transmitCommand(oversized);

        assertEquals(ISO7816.SW_WRONG_LENGTH, response.getSW());
    }
}
