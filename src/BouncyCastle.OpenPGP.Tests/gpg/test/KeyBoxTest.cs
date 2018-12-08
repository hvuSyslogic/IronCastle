using org.bouncycastle.bcpg;

namespace org.bouncycastle.gpg.test
{

	using TestCase = junit.framework.TestCase;
	using PublicKeyAlgorithmTags = org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
	using BlobType = org.bouncycastle.gpg.keybox.BlobType;
	using CertificateBlob = org.bouncycastle.gpg.keybox.CertificateBlob;
	using FirstBlob = org.bouncycastle.gpg.keybox.FirstBlob;
	using KeyBlob = org.bouncycastle.gpg.keybox.KeyBlob;
	using KeyBox = org.bouncycastle.gpg.keybox.KeyBox;
	using PublicKeyRingBlob = org.bouncycastle.gpg.keybox.PublicKeyRingBlob;
	using BcBlobVerifier = org.bouncycastle.gpg.keybox.bc.BcBlobVerifier;
	using BcKeyBox = org.bouncycastle.gpg.keybox.bc.BcKeyBox;
	using JcaKeyBoxBuilder = org.bouncycastle.gpg.keybox.jcajce.JcaKeyBoxBuilder;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using PGPPublicKey = org.bouncycastle.openpgp.PGPPublicKey;
	using PGPPublicKeyRing = org.bouncycastle.openpgp.PGPPublicKeyRing;
	using BcKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.bc.BcKeyFingerprintCalculator;
	using Streams = org.bouncycastle.util.io.Streams;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class KeyBoxTest : SimpleTest
	{
		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new KeyBoxTest());
		}

		public override string getName()
		{
			return "KeyBoxTest";
		}

		/// <summary>
		/// Test loading a key store and extracting information.
		/// </summary>
		/// <exception cref="Exception"> </exception>
		public virtual void testSuccessfulLoad()
		{
			loadCheck(new BcKeyBox(typeof(KeyBoxTest).getResourceAsStream("/pgpdata/pubring.kbx")));
			loadCheck((new JcaKeyBoxBuilder()).build(typeof(KeyBoxTest).getResourceAsStream("/pgpdata/pubring.kbx")));
		}

		private void loadCheck(KeyBox keyBox)
		{

			FirstBlob firstBlob = keyBox.getFirstBlob();


			//
			// Check the first blob.
			//
			TestCase.assertEquals(BlobType.FIRST_BLOB, firstBlob.getType());
			TestCase.assertEquals("Version", 1, firstBlob.getVersion());
			TestCase.assertEquals("Header flags.", 2, firstBlob.getHeaderFlags());
			TestCase.assertEquals("Created at date.", 1526963333, firstBlob.getFileCreatedAt());
			TestCase.assertEquals("Last maintained date.", 1526963333, firstBlob.getLastMaintenanceRun());

			// Number of blobs.
			TestCase.assertEquals("Two material blobs.", 2, keyBox.getKeyBlobs().size());


			foreach (KeyBlob keyBlob in keyBox.getKeyBlobs())
			{

				switch (keyBlob.getType())
				{
				case X509_BLOB:
				{
					TestCase.assertEquals(2, keyBlob.getUserIds().size());
					TestCase.assertEquals(keyBlob.getNumberOfUserIDs(), keyBlob.getUserIds().size());

					// Self signed.
					TestCase.assertEquals("CN=Peggy Shippen", keyBlob.getUserIds().get(0).getUserIDAsString());
					TestCase.assertEquals("CN=Peggy Shippen", keyBlob.getUserIds().get(1).getUserIDAsString());

					// It can be successfully parsed into a certificate.


					byte[] certData = ((CertificateBlob)keyBlob).getEncodedCertificate();
					CertificateFactory factory = CertificateFactory.getInstance("X509");
					factory.generateCertificate(new ByteArrayInputStream(certData));

					TestCase.assertEquals(1, keyBlob.getKeyInformation().size());
					TestCase.assertEquals(20, keyBlob.getKeyInformation().get(0).getFingerprint().length);
					TestCase.assertNull(keyBlob.getKeyInformation().get(0).getKeyID());
				}
				break;


				case OPEN_PGP_BLOB:
					TestCase.assertEquals(1, keyBlob.getUserIds().size());
					TestCase.assertEquals(keyBlob.getNumberOfUserIDs(), keyBlob.getUserIds().size());
					TestCase.assertEquals("Walter Mitty <walter@mitty.local>", keyBlob.getUserIds().get(0).getUserIDAsString());

					//
					// It can be successfully parsed.
					//
					((PublicKeyRingBlob)keyBlob).getPGPPublicKeyRing();

					TestCase.assertEquals(2, keyBlob.getKeyInformation().size());
					TestCase.assertEquals(20, keyBlob.getKeyInformation().get(0).getFingerprint().length);
					TestCase.assertNotNull(keyBlob.getKeyInformation().get(0).getKeyID());

					TestCase.assertEquals(20, keyBlob.getKeyInformation().get(1).getFingerprint().length);
					TestCase.assertNotNull(keyBlob.getKeyInformation().get(1).getKeyID());

					break;

				default:
					TestCase.fail("Unexpected blob type: " + keyBlob.getType());
				break;
				}
			}

		}

		/// <summary>
		/// Test load kb with El Gamal keys in it.
		/// </summary>
		/// <exception cref="Exception"> </exception>
		public virtual void testSanityElGamal()
		{
			testSanityElGamal_verify(new BcKeyBox(typeof(KeyBoxTest).getResourceAsStream("/pgpdata/eg_pubring.kbx")));
			testSanityElGamal_verify((new JcaKeyBoxBuilder()).setProvider("BC").build(typeof(KeyBoxTest).getResourceAsStream("/pgpdata/eg_pubring.kbx")));
		}

		private void testSanityElGamal_verify(KeyBox keyBox)
		{
			FirstBlob firstBlob = keyBox.getFirstBlob();


			//
			// Check the first blob.
			//
			TestCase.assertEquals(BlobType.FIRST_BLOB, firstBlob.getType());
			TestCase.assertEquals("Version", 1, firstBlob.getVersion());
			TestCase.assertEquals("Header flags.", 2, firstBlob.getHeaderFlags());
			TestCase.assertEquals("Created at date.", 1527840866, firstBlob.getFileCreatedAt());
			TestCase.assertEquals("Last maintained date.", 1527840866, firstBlob.getLastMaintenanceRun());

			// Number of blobs.
			TestCase.assertEquals("One material blobs.", 1, keyBox.getKeyBlobs().size());

			TestCase.assertEquals("Pgp type", BlobType.OPEN_PGP_BLOB, keyBox.getKeyBlobs().get(0).getType());

			PublicKeyRingBlob pgkr = (PublicKeyRingBlob)keyBox.getKeyBlobs().get(0);
			PGPPublicKeyRing ring = pgkr.getPGPPublicKeyRing();

			TestCase.assertEquals("Must be DSA", PublicKeyAlgorithmTags_Fields.DSA, ring.getPublicKey().getAlgorithm());

			Iterator<PGPPublicKey> it = ring.getPublicKeys();
			it.next();
			TestCase.assertEquals("Must be ELGAMAL_ENCRYPT", PublicKeyAlgorithmTags_Fields.ELGAMAL_ENCRYPT, it.next().getAlgorithm());
		}


		/// <summary>
		/// Induce a checksum failure in the first key block.
		/// </summary>
		/// <exception cref="Exception"> </exception>
		public virtual void testInducedChecksumFailed()
		{

			byte[] raw = Streams.readAll(typeof(KeyBoxTest).getResourceAsStream("/pgpdata/pubring.kbx"));

			raw[36] ^= 1; // Single bit error in first key block.


			// BC
			try
			{
				new KeyBox(raw, new BcKeyFingerprintCalculator(), new BcBlobVerifier());
				fail("Must have invalid checksum");
			}
			catch (IOException ioex)
			{
				isEquals("Blob with base offset of 32 has incorrect digest.", ioex.Message);
			}

			// JCA
			try
			{
				(new JcaKeyBoxBuilder()).setProvider("BC").build(raw);
				fail("Must have invalid checksum");
			}
			catch (IOException ioex)
			{
				isEquals("Blob with base offset of 32 has incorrect digest.", ioex.Message);
			}

		}


		public virtual void testBrokenMagic()
		{
			byte[] raw = Streams.readAll(typeof(KeyBoxTest).getResourceAsStream("/pgpdata/pubring.kbx"));

			raw[8] ^= 1; // Single bit error in magic number.

			// BC
			try
			{
				new KeyBox(raw, new BcKeyFingerprintCalculator(), new BcBlobVerifier());
				fail("Must have invalid magic");
			}
			catch (IOException ioex)
			{
				isEquals("Incorrect magic expecting 4b425866 but got 4a425866", ioex.Message);
			}


			// JCA
			try
			{
				(new JcaKeyBoxBuilder()).setProvider("BC").build(raw);
				fail("Must have invalid checksum");
			}
			catch (IOException ioex)
			{
				isEquals("Incorrect magic expecting 4b425866 but got 4a425866", ioex.Message);
			}
		}

		public virtual void testNullSource()
		{
			InputStream zulu = null;

			// BC
			try
			{
				new KeyBox(zulu, new BcKeyFingerprintCalculator(), new BcBlobVerifier());
				fail("Must fail.");
			}
			catch (IllegalArgumentException ioex)
			{
				isEquals("Cannot take get instance of null", ioex.getMessage());
			}

			// JCA
			try
			{
				(new JcaKeyBoxBuilder()).setProvider("BC").build(zulu);
				fail("Must fail.");
			}
			catch (IllegalArgumentException ioex)
			{
				isEquals("Cannot take get instance of null", ioex.getMessage());
			}

		}


		public virtual void testNoFirstBlob()
		{
			// BC
			try
			{
				new KeyBox(new byte[0], new BcKeyFingerprintCalculator(), new BcBlobVerifier());
				fail("Must fail.");
			}
			catch (IOException ioex)
			{
				isEquals("No first blob, is the source zero length?", ioex.Message);
			}

			// JCA
			try
			{
				(new JcaKeyBoxBuilder()).setProvider("BC").build(new byte[0]);
				fail("Must fail.");
			}
			catch (IOException ioex)
			{
				isEquals("No first blob, is the source zero length?", ioex.Message);
			}

		}

		public virtual void testDoubleFirstBlob()
		{
			// BC
			try
			{
				new KeyBox(typeof(KeyBoxTest).getResourceAsStream("/pgpdata/doublefirst.kbx"), new BcKeyFingerprintCalculator(), new BcBlobVerifier());
				fail("Must fail.");
			}
			catch (IOException ioex)
			{
				isEquals("Unexpected second 'FirstBlob', there should only be one FirstBlob at the start of the file.", ioex.Message);
			}


			// JCA
			try
			{
				(new JcaKeyBoxBuilder()).setProvider("BC").build(typeof(KeyBoxTest).getResourceAsStream("/pgpdata/doublefirst.kbx"));
				fail("Must fail.");
			}
			catch (IOException ioex)
			{
				isEquals("Unexpected second 'FirstBlob', there should only be one FirstBlob at the start of the file.", ioex.Message);
			}
		}

		public virtual void testKeyBoxWithMD5Sanity()
		{
			//
			// Expect no failure.
			//
			new BcKeyBox(typeof(KeyBoxTest).getResourceAsStream("/pgpdata/md5kbx.kbx"));
			(new JcaKeyBoxBuilder()).build(typeof(KeyBoxTest).getResourceAsStream("/pgpdata/md5kbx.kbx"));
		}

		public virtual void testKeyBoxWithBrokenMD5()
		{
			byte[] raw = Streams.readAll(typeof(KeyBoxTest).getResourceAsStream("/pgpdata/md5kbx.kbx"));

			raw[36] ^= 1; // Single bit error in first key block.

			// BC
			try
			{
				new KeyBox(raw, new BcKeyFingerprintCalculator(), new BcBlobVerifier());
				fail("Must have invalid checksum");
			}
			catch (IOException ioex)
			{
				isEquals("Blob with base offset of 32 has incorrect digest.", ioex.Message);
			}

			// JCA
			try
			{
				(new JcaKeyBoxBuilder()).setProvider("BC").build(raw);
				fail("Must have invalid checksum");
			}
			catch (IOException ioex)
			{
				isEquals("Blob with base offset of 32 has incorrect digest.", ioex.Message);
			}


		}

		public override void performTest()
		{
			testNoFirstBlob();
			testSanityElGamal();
			testKeyBoxWithBrokenMD5();
			testKeyBoxWithMD5Sanity();
			testDoubleFirstBlob();
			testNullSource();
			testBrokenMagic();
			testSuccessfulLoad();
			testInducedChecksumFailed();
		}

	}

}