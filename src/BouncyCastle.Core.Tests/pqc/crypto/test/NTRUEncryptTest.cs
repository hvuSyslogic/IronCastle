using System;

namespace org.bouncycastle.pqc.crypto.test
{

	using TestCase = junit.framework.TestCase;
	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using DataLengthException = org.bouncycastle.crypto.DataLengthException;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;
	using NTRUEncryptionKeyGenerationParameters = org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionKeyGenerationParameters;
	using NTRUEncryptionKeyPairGenerator = org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionKeyPairGenerator;
	using NTRUEncryptionPrivateKeyParameters = org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionPrivateKeyParameters;
	using NTRUEncryptionPublicKeyParameters = org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionPublicKeyParameters;
	using NTRUEngine = org.bouncycastle.pqc.crypto.ntru.NTRUEngine;
	using NTRUParameters = org.bouncycastle.pqc.crypto.ntru.NTRUParameters;
	using DenseTernaryPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial;
	using IntegerPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.IntegerPolynomial;
	using Polynomial = org.bouncycastle.pqc.math.ntru.polynomial.Polynomial;
	using SparseTernaryPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.SparseTernaryPolynomial;
	using TernaryPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.TernaryPolynomial;
	using Arrays = org.bouncycastle.util.Arrays;

	public class NTRUEncryptTest : TestCase
	{
		public virtual void testEncryptDecrypt()
		{
			NTRUEncryptionKeyGenerationParameters @params = NTRUEncryptionKeyGenerationParameters.APR2011_743.clone();
			// set df1..df3 and dr1..dr3 so params can be used for SIMPLE as well as PRODUCT
			@params.df1 = NTRUEncryptionKeyGenerationParameters.APR2011_743_FAST.df1;
			@params.df2 = NTRUEncryptionKeyGenerationParameters.APR2011_743_FAST.df2;
			@params.df3 = NTRUEncryptionKeyGenerationParameters.APR2011_743_FAST.df3;
			@params.dr1 = NTRUEncryptionKeyGenerationParameters.APR2011_743_FAST.dr1;
			@params.dr2 = NTRUEncryptionKeyGenerationParameters.APR2011_743_FAST.dr2;
			@params.dr3 = NTRUEncryptionKeyGenerationParameters.APR2011_743_FAST.dr3;

			int[] values = new int[] {NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE, NTRUParameters.TERNARY_POLYNOMIAL_TYPE_PRODUCT};

			for (int i = 0; i != values.Length; i++)
			{
				int polyType = values[i];

				bool[] booleans = new bool[] {true, false};
				for (int j = 0; j != booleans.Length; j++)
				{
					@params.polyType = polyType;
					@params.fastFp = booleans[j];

					VisibleNTRUEngine ntru = new VisibleNTRUEngine(this);
					NTRUEncryptionKeyPairGenerator ntruGen = new NTRUEncryptionKeyPairGenerator();

					ntruGen.init(@params);

					AsymmetricCipherKeyPair kp = ntruGen.generateKeyPair();

					testPolynomial(ntru, kp, @params);

					testText(ntru, kp, @params);
					// sparse/dense
					@params.sparse = !@params.sparse;
					testText(ntru, kp, @params);
					@params.sparse = !@params.sparse;

					testEmpty(ntru, kp, @params);
					testMaxLength(ntru, kp, @params);
					testTooLong(ntru, kp, @params);
					testInvalidEncoding(ntru, kp, @params);
				}
			}
		}

		// encrypts and decrypts a polynomial
		private void testPolynomial(VisibleNTRUEngine ntru, AsymmetricCipherKeyPair kp, NTRUEncryptionKeyGenerationParameters @params)
		{
			SecureRandom random = new SecureRandom();
			IntegerPolynomial m = DenseTernaryPolynomial.generateRandom(@params.N, random);
			SparseTernaryPolynomial r = SparseTernaryPolynomial.generateRandom(@params.N, @params.dr, @params.dr, random);

			ntru.init(true, kp.getPublic()); // just to set params

			IntegerPolynomial e = ntru.encrypt(m, r, ((NTRUEncryptionPublicKeyParameters)kp.getPublic()).h);
			IntegerPolynomial c = ntru.decrypt(e, ((NTRUEncryptionPrivateKeyParameters)kp.getPrivate()).t, ((NTRUEncryptionPrivateKeyParameters)kp.getPrivate()).fp);

			assertTrue(Arrays.areEqual(m.coeffs, c.coeffs));
		}

		// encrypts and decrypts text
		private void testText(NTRUEngine ntru, AsymmetricCipherKeyPair kp, NTRUEncryptionKeyGenerationParameters @params)
		{
			byte[] plainText = "text to encrypt".GetBytes();

			ntru.init(true, kp.getPublic());

			byte[] encrypted = ntru.processBlock(plainText, 0, plainText.Length);

			ntru.init(false, kp.getPrivate());

			byte[] decrypted = ntru.processBlock(encrypted, 0, encrypted.Length);

			assertTrue(Arrays.areEqual(plainText, decrypted));
		}

		// tests an empty message
		private void testEmpty(NTRUEngine ntru, AsymmetricCipherKeyPair kp, NTRUEncryptionKeyGenerationParameters @params)
		{
			byte[] plainText = "".GetBytes();

			ntru.init(true, kp.getPublic());

			byte[] encrypted = ntru.processBlock(plainText, 0, plainText.Length);

			ntru.init(false, kp.getPrivate());

			byte[] decrypted = ntru.processBlock(encrypted, 0, encrypted.Length);

			assertTrue(Arrays.areEqual(plainText, decrypted));
		}

		// tests a message of the maximum allowed length
		private void testMaxLength(NTRUEngine ntru, AsymmetricCipherKeyPair kp, NTRUEncryptionKeyGenerationParameters @params)
		{
			byte[] plainText = new byte[@params.maxMsgLenBytes];
			JavaSystem.arraycopy("secret encrypted text".GetBytes(), 0, plainText, 0, 21);
			ntru.init(true, kp.getPublic());

			byte[] encrypted = ntru.processBlock(plainText, 0, plainText.Length);

			ntru.init(false, kp.getPrivate());

			byte[] decrypted = ntru.processBlock(encrypted, 0, encrypted.Length);

			assertTrue(Arrays.areEqual(plainText, decrypted));
		}

		// tests a message that is too long
		private void testTooLong(NTRUEngine ntru, AsymmetricCipherKeyPair kp, NTRUEncryptionKeyGenerationParameters @params)
		{
			byte[] plainText = new byte[@params.maxMsgLenBytes + 1];
			try
			{
				JavaSystem.arraycopy("secret encrypted text".GetBytes(), 0, plainText, 0, 21);

				ntru.init(true, kp.getPublic());

				byte[] encrypted = ntru.processBlock(plainText, 0, plainText.Length);

				ntru.init(false, kp.getPrivate());

				byte[] decrypted = ntru.processBlock(encrypted, 0, encrypted.Length);

				assertTrue(Arrays.areEqual(plainText, decrypted));
				fail("An exception should have been thrown!");
			}
			catch (DataLengthException ex)
			{
				assertEquals("Message too long: " + plainText.Length + ">" + @params.maxMsgLenBytes, ex.Message);
			}
			catch (InvalidCipherTextException e)
			{
				Console.WriteLine(e.ToString());
				Console.Write(e.StackTrace); //To change body of catch statement use File | Settings | File Templates.
			}
		}

		// tests that altering the public key *AFTER* encryption causes the decrypted message to be rejected
		private void testInvalidEncoding(NTRUEngine ntru, AsymmetricCipherKeyPair kp, NTRUEncryptionKeyGenerationParameters @params)
		{
			try
			{
				byte[] plainText = "secret encrypted text".GetBytes();
				ntru.init(true, kp.getPublic());

				byte[] encrypted = ntru.processBlock(plainText, 0, plainText.Length);

				NTRUEncryptionPrivateKeyParameters orig = (NTRUEncryptionPrivateKeyParameters)kp.getPrivate();
				IntegerPolynomial h = (IntegerPolynomial)((NTRUEncryptionPublicKeyParameters)kp.getPublic()).h.clone();
				h.coeffs[0] = (h.coeffs[0] + 111) % @params.q; // alter h
				NTRUEncryptionPrivateKeyParameters privKey = new NTRUEncryptionPrivateKeyParameters(h, orig.t, orig.fp, @params.getEncryptionParameters());

				ntru.init(false, privKey);

				ntru.processBlock(encrypted, 0, encrypted.Length);

				fail("An exception should have been thrown!");
			}
			catch (InvalidCipherTextException ex)
			{
				assertEquals("Invalid message encoding", ex.Message);
			}
		}

		// encrypts and decrypts text using an encoded key pair (fastFp=false, simple ternary polynomials)
		public virtual void testEncodedKeysSlow()
		{
			byte[] plainText = "secret encrypted text".GetBytes();

			// dense polynomials
			NTRUEncryptionKeyGenerationParameters @params = NTRUEncryptionKeyGenerationParameters.APR2011_743;
			NTRUEngine ntru = new NTRUEngine();

			byte[] privBytes = new byte[] {2, -94, 95, 65, -107, 27, 98, 62, -15, -62, 21, -4, 119, -117, 7, 68, 100, 113, -36, -82, 87, -87, -82, 24, -45, -75, -74, -108, 105, 24, 123, 117, 124, 74, -27, 42, -106, -78, 114, 27, 18, 77, -41, 105, -113, 39, 49, 46, 109, -69, 61, 77, 49, 117, 14, -29, 42, 3, 120, -121, -120, -37, 95, 84, 60, -9, -31, -64, 31, 72, 115, -15, 21, -6, 27, -60, -73, -29, -33, -81, -43, 106, 65, 114, 102, -14, -115, -96, 9, 54, 23, -18, -24, -76, 84, -41, -79, 35, 88, 11, 41, 67, 44, -63, -28, 76, 84, -41, -103, 106, -22, 35, -2, -40, -48, -121, -128, 76, 63, 123, -11, 103, -35, -32, 21, -51, -99, -40, -103, -12, 64, -80, 57, -56, 1, -51, 103, 83, 50, 111, -87, -98, 7, -109, 25, -51, 23, -92};
			byte[] pubBytes = new byte[] {91, -66, -25, -81, -66, -33, 25, -31, 48, 23, -38, 20, -30, -120, -17, 1, 21, 51, -11, 102, -50, 62, 71, 79, 32, -49, -57, 105, 21, -34, -45, -67, 113, -46, -103, 57, 28, -54, -21, 94, -112, -63, 105, -100, -95, 21, -52, 50, 11, -22, -63, -35, -42, 50, 93, -40, 23, 0, 121, 23, -93, 111, -98, -14, 92, -24, -117, -8, -109, -118, -4, -107, -60, 100, -128, -47, -92, -117, -108, 39, -113, 43, 48, 68, 95, 123, -112, 41, -27, -99, 59, 33, -57, -120, -44, 72, -98, -105, -91, -52, -89, 107, 119, 87, -36, -102, -83, 67, -8, 30, -54, 74, 93, 119, -3, 126, 69, -104, -44, -24, 124, 108, -125, 73, 98, 121, -49, -37, -24, 87, -71, 91, 8, -31, -50, 95, 112, 27, 97, -93, 3, -73, -54, -16, -92, -108, -74, 88, -5, 23, 70, 69, -49, -46, -50, 65, 69, -54, -41, 109, 8, -80, -23, -84, 120, -77, 26, 99, -104, -33, 82, 91, 22, -17, 113, -29, 66, -7, -114, -101, -111, -47, -1, -3, -57, 62, 79, -70, -58, 45, 76, 28, -117, 59, -117, 113, 84, -55, 48, 119, 58, -105, -20, 80, 102, 14, -69, -69, 5, 11, -87, 107, 15, 105, -69, -27, -24, 47, -18, -54, -45, -67, 27, -52, -20, -94, 64, -26, -58, 98, 33, -61, 71, -101, 120, 28, 113, 72, 127, 50, 123, 36, -97, 78, 32, -74, 105, 62, 92, 84, -17, 21, -75, 24, -90, -78, -4, -121, 47, -82, 119, 27, -61, 17, -66, 43, 96, -49, -6, 66, -13, -75, -95, 64, -12, -39, 111, 46, -3, -123, 82, 12, -26, -30, -29, 71, -108, -79, -112, 13, 16, -70, 7, 100, 84, 89, -100, 114, 47, 56, 71, 83, 63, -61, -39, -53, -100, 23, -31, -52, -46, 36, -13, 62, 107, 28, -28, 92, 116, -59, 28, -111, -23, -44, 21, -2, 127, -112, 54, -126, 13, -104, 47, -43, -109, -19, 107, -94, -126, 50, 92, -69, 1, 115, -121, -52, -100, 25, 126, -7, 86, 77, 72, -2, -104, -42, 98, -16, 54, -67, 117, 14, -73, 4, 58, 121, 35, 1, 99, -127, -9, -60, 32, -37, -106, 6, -108, -13, -62, 23, -20, -9, 21, 15, 4, 126, -112, 123, 34, -67, -51, 43, -30, -75, 119, -112, -58, -55, -90, 2, -5, -46, -12, 119, 87, 24, -52, 2, -29, 113, 61, -82, -101, 57, -11, -107, -11, 67, -42, -43, -13, 112, -49, 82, 60, 13, -50, 108, 64, -64, 53, -107, -9, 102, -33, 75, -100, -115, 102, -113, -48, 19, -119, -72, -65, 22, -65, -93, 34, -71, 75, 101, 54, 126, 75, 34, -21, -53, -36, 127, -21, 70, 24, 89, -88, 63, -43, -4, 68, 97, -45, -101, -125, -38, 98, -118, -34, -63, 23, 78, 15, 17, 101, -107, 119, -41, 107, 117, 17, 108, 43, -93, -6, -23, -30, 49, -61, 27, 61, -125, -68, 51, 40, -106, -61, 51, 127, 2, 123, 7, -50, -115, -32, -95, -96, 67, 4, 5, 59, -45, 61, 95, 14, 2, -76, -121, 8, 125, 16, -126, 58, 118, -32, 19, -113, -113, 120, -101, 86, 76, -90, 50, -92, 51, -92, 1, 121, -74, -101, -33, 53, -53, -83, 46, 20, -87, -112, -61, -87, 106, -126, 64, 99, -60, 70, 120, 47, -53, 36, 20, -90, 110, 61, -93, 55, -10, 85, 45, 52, 79, 87, 100, -81, -85, 34, 55, -91, 27, 116, -18, -71, -11, 87, -11, 76, 48, 97, -78, 64, -100, -59, -12, 19, -90, 121, 48, -19, 64, 113, -70, -14, -70, 92, 124, 42, 95, 7, -115, 36, 127, 73, 33, 30, 121, 88, 16, -90, 99, 120, -68, 64, -125, -78, 76, 112, 68, 8, 105, 10, -47, -124, 39, -107, -101, 46, -61, 118, -74, 102, -62, -6, -128, 17, -45, 61, 76, 63, -10, -41, 50, -113, 75, -83, -59, -51, -23, -61, 47, 7, -80, 126, -2, 79, -53, 110, -93, -38, -91, -22, 20, -84, -113, -124, -73, 124, 0, 33, -58, 63, -26, 52, 7, 74, 65, 38, -33, 21, -9, -1, 120, -16, 47, -96, 59, -64, 74, 6, 48, -67, -32, -26, 35, 68, 47, 82, 36, 52, 41, 112, -28, -22, -51, -6, -49, 105, 16, -34, 99, -41, 75, 7, 79, -22, -125, -30, -126, 35, 119, -43, -30, 32, 8, 44, -42, -98, 78, -92, -95, -10, -94, -1, -91, -122, 77, 0, 40, -23, 36, 85, 123, -57, -74, -69, -90, 89, 111, -120, 22, 5, -48, 114, 59, 31, 31, -25, -3, 24, 110, -110, 73, -40, 92, -26, -12, 52, 83, -98, -119, -6, -117, -89, 95, 83, -25, 122, -26, 114, 81, 25, 110, 79, -49, -39, 10, -78, -65, 57, -90, -46, -126, 15, -124, -104, -89, -66, -87, 24, -45, 39, -34, -40, -13, 106, 12, -25, -116, -47, 79, -81, 64, -17, -31, -70, 87, 36, 46, 102, 107, 48, 88, 34, 46, 24, 63, -100, 106, 27, 58, -71, 38, 60, -66, 45, -89, 39, -60, -116, -14, -119, 118, 0, -24, -9, 38, -71, -79, 124, -119, -64, -9, 71, -56, -82, -73, -69, 127, -1, -20, 123, 32, -43, 49, 5, 49, 105, -5, -2, 5, -105, -111, 89, -30, -41, -49, 61, 80, 69, 44, -33, -116, -45, -96, 63, 28, -17, -106, -94, 90, -40, -88, 122, 116, 116, 113, -65, 104, 119, -3, 96, -45, 18, -120, -111, 83, 43, -5, 101, 71, 48, 104, -112, -95, -46, 53, -96, -93, -126, 96, 56, 104, -111, 114, -1, -44, -120, -112, -19, 100, 41, -122, 23, -78, 33, -35, 11, 57, -18, 106, -40, 74, 61, 66, 54, -77, 96, 70, 108, -128, 91, -97, -36, -23, -86, -91, 44, 58, 117, 2, 26, 44, 95, 79, -101, -81, -92, 110, -81, -12, -88, -21, -83, 60, 93, -121, -114, -48, -34, -119, -1, 127, -121, 54, -128, -106, -39, -108, 81, 17, -3, -13, -57, 74, 41, -122, -65, -107, -118, -65, -61, 103, -69, 19};

			byte[] fullBytes = new byte[pubBytes.Length + privBytes.Length];

			JavaSystem.arraycopy(pubBytes, 0, fullBytes, 0, pubBytes.Length);
			JavaSystem.arraycopy(privBytes, 0, fullBytes, pubBytes.Length, privBytes.Length);

			NTRUEncryptionPrivateKeyParameters priv = new NTRUEncryptionPrivateKeyParameters(fullBytes, @params.getEncryptionParameters());
			NTRUEncryptionPublicKeyParameters pub = new NTRUEncryptionPublicKeyParameters(pubBytes, @params.getEncryptionParameters());
			AsymmetricCipherKeyPair kp = new AsymmetricCipherKeyPair(pub, priv);

			ntru.init(true, kp.getPublic());

			byte[] encrypted = ntru.processBlock(plainText, 0, plainText.Length);

			ntru.init(false, kp.getPrivate());

			byte[] decrypted = ntru.processBlock(encrypted, 0, encrypted.Length);
			assertTrue(Arrays.areEqual(plainText, decrypted));

			// sparse polynomials
			@params = NTRUEncryptionKeyGenerationParameters.EES1499EP1;
			ntru = new NTRUEngine();
			privBytes = new byte[] {116, 7, 118, 121, 6, 77, (byte)-36, 60, 65, 108, 10, (byte)-106, 12, 9, (byte)-22, (byte)-113, 122, (byte)-31, (byte)-31, 18, 120, 81, (byte)-33, 5, 122, (byte)-76, 109, (byte)-30, (byte)-101, (byte)-45, 21, 13, (byte)-11, (byte)-49, (byte)-111, 46, 91, 4, (byte)-28, (byte)-109, 121, (byte)-119, (byte)-121, (byte)-58, (byte)-113, (byte)-9, (byte)-10, (byte)-25, (byte)-53, 40, (byte)-86, (byte)-22, (byte)-50, 42, 52, 107, 119, 17, 33, 125, (byte)-26, 33, 55, 25, (byte)-77, (byte)-65, (byte)-106, 116, (byte)-67, 91, 105, (byte)-7, 42, (byte)-107, (byte)-54, 101, 12, (byte)-12, 57, (byte)-116, 45, (byte)-107, (byte)-17, 110, 35, (byte)-64, 19, (byte)-38, (byte)-122, 115, (byte)-93, 53, 69, 66, (byte)-106, 17, 20, (byte)-71, 121, 23, (byte)-21, (byte)-45, 108, 97, 23, (byte)-98, (byte)-12, (byte)-41, (byte)-31, (byte)-53, 30, (byte)-42, 15, 85, (byte)-21, (byte)-89, 118, 42, (byte)-117, (byte)-39, 69, 0, (byte)-63, 83, 48, (byte)-80, (byte)-14, (byte)-123, (byte)-4, (byte)-116, (byte)-90, (byte)-107, (byte)-89, 119, 29, (byte)-30, 69, 22, (byte)-84, 47, 117, (byte)-123, 102, (byte)-116, 35, 93, (byte)-13, 84, (byte)-9, (byte)-122, 58, 101, 93, (byte)-106, (byte)-119, (byte)-35, (byte)-75, 76, 27, (byte)-125, (byte)-22, 68, 101, 49, 103, (byte)-13, (byte)-98, 93, (byte)-56, (byte)-110, (byte)-19, (byte)-12, 74, 104, 7, 6, (byte)-11, 47, 57, 90, 75, (byte)-30, 47, 66, (byte)-58, 14, 14, 70, 11, (byte)-119, (byte)-36, (byte)-118, (byte)-55, (byte)-53, 101, (byte)-73, (byte)-77, 33, (byte)-29, 96, (byte)-86, 38, 47, 103, 19, (byte)-37, (byte)-17, (byte)-50, (byte)-82, (byte)-87, (byte)-119, 37, (byte)-54, 77, (byte)-69, (byte)-16, (byte)-48, (byte)-52, 110, (byte)-26, 111, 35, 26, (byte)-53, (byte)-10, 9, (byte)-108, (byte)-34, 102, 7, (byte)-18, (byte)-72, (byte)-26, 24, (byte)-50, (byte)-43, 92, 56, (byte)-94, 23, (byte)-36, 60, 28, (byte)-121, 27, 127, (byte)-93, (byte)-79, (byte)-45, (byte)-60, 105, (byte)-6, (byte)-88, 72, (byte)-41, 47, (byte)-51, 3, 91, 116, 75, 122, (byte)-94, (byte)-113, 28, (byte)-96, (byte)-62, (byte)-29, (byte)-74, (byte)-85, (byte)-93, 51, 58, 72, 44, 9, 18, (byte)-48, (byte)-24, 73, 122, 60, (byte)-23, 83, (byte)-110, (byte)-7, (byte)-111, (byte)-69, 106, 51, 118, (byte)-83, (byte)-18, 109, (byte)-32, 40, 22};

			pubBytes = new byte[] {(byte)-62, 56, 59, (byte)-46, 30, (byte)-19, 22, (byte)-115, (byte)-20, 117, (byte)-14, 3, 2, (byte)-57, 85, (byte)-24, 27, 57, 49, (byte)-93, (byte)-52, 87, 49, 96, 15, 95, (byte)-95, (byte)-86, (byte)-61, 50, (byte)-18, 3, 109, (byte)-55, (byte)-110, (byte)-57, 82, 124, (byte)-5, (byte)-57, 68, (byte)-18, 126, 114, 6, (byte)-22, 8, 121, 125, 29, (byte)-16, 112, (byte)-81, 27, (byte)-7, 109, (byte)-44, (byte)-123, (byte)-15, (byte)-14, 74, (byte)-126, 95, (byte)-94, (byte)-91, 119, 80, (byte)-48, 41, 49, 6, 104, 93, (byte)-97, (byte)-108, (byte)-82, 93, 70, (byte)-127, (byte)-113, (byte)-22, (byte)-103, 35, (byte)-115, 20, (byte)-115, 63, 57, (byte)-84, (byte)-18, (byte)-107, 81, 44, (byte)-16, 83, 71, (byte)-27, (byte)-2, (byte)-125, 87, 26, 100, (byte)-116, 110, 94, (byte)-46, (byte)-56, (byte)-82, 119, (byte)-110, (byte)-127, (byte)-99, (byte)-8, (byte)-118, 90, 64, (byte)-29, 102, 99, 92, 86, (byte)-117, 26, (byte)-89, 32, 17, 55, (byte)-65, (byte)-10, (byte)-5, (byte)-74, 19, 13, 113, (byte)-15, (byte)-103, 17, 10, (byte)-127, (byte)-95, (byte)-79, 19, 11, (byte)-24, 59, 28, (byte)-70, (byte)-55, (byte)-69, (byte)-105, (byte)-20, (byte)-117, 66, 4, 77, 116, (byte)-124, (byte)-62, 19, 109, 49, (byte)-120, 10, (byte)-15, 108, 84, 126, 122, (byte)-46, (byte)-37, 114, (byte)-78, (byte)-72, 34, (byte)-12, 25, (byte)-104, (byte)-3, 114, (byte)-94, 16, 31, 31, (byte)-124, (byte)-109, (byte)-64, 57, (byte)-47, (byte)-113, (byte)-26, 97, (byte)-58, 112, (byte)-40, 49, 80, (byte)-54, (byte)-115, (byte)-98, (byte)-60, (byte)-123, 91, 14, 75, (byte)-86, 77, (byte)-93, 68, 112, 82, 79, 28, (byte)-25, 49, (byte)-27, (byte)-112, 103, 60, (byte)-128, 95, (byte)-63, 2, (byte)-51, 2, (byte)-107, 80, 113, 18, 123, 24, 70, 77, (byte)-56, (byte)-48, 33, 89, 88, 29, 112, (byte)-102, (byte)-15, 52, (byte)-96, 17, (byte)-9, 6, (byte)-11, (byte)-119, 29, (byte)-107, (byte)-84, (byte)-19, 84, 124, 19, 90, (byte)-60, (byte)-41, 123, (byte)-81, 96, (byte)-119, 17, (byte)-61, 62, 55, 95, (byte)-73, (byte)-13, (byte)-60, 56, 77, 24, (byte)-39, (byte)-107, (byte)-78, 47, (byte)-91, 88, 90, 34, 112, (byte)-80, 83, (byte)-58, 127, 76, (byte)-97, (byte)-40, 78, (byte)-20, (byte)-1, (byte)-62, 19, 6, (byte)-43, (byte)-46, (byte)-36, (byte)-53, (byte)-22, (byte)-28, (byte)-119, 8, 19, 79, (byte)-9, (byte)-54, (byte)-126, (byte)-3, (byte)-20, (byte)-110, (byte)-82, 51, 3, 1, (byte)-123, (byte)-41, (byte)-40, (byte)-11, 91, (byte)-52, 48, 104, (byte)-11, (byte)-2, 49, 45, 52, (byte)-33, 109, (byte)-44, (byte)-30, (byte)-44, (byte)-83, (byte)-108, (byte)-10, 77, 106, 82, 3, 14, (byte)-48, (byte)-18, (byte)-79, (byte)-64, (byte)-34, (byte)-63, (byte)-18, 122, 33, 25, 44, 82, (byte)-112, 111, 68, 97, (byte)-58, (byte)-38, 25, 62, 78, 97, (byte)-36, 57, (byte)-19, 122, (byte)-18, (byte)-74, 67, (byte)-127, (byte)-24, 32, (byte)-45, 67, (byte)-106, 90, 0, 1, 91, 30, (byte)-80, 95, 9, 78, (byte)-4, (byte)-14, 16, 111, (byte)-56, (byte)-102, (byte)-90, 52, (byte)-1, 116, 19, (byte)-127, (byte)-23, (byte)-87, 103, (byte)-94, (byte)-111, 118, 53, (byte)-69, 77, 17, (byte)-3, 31, (byte)-53, (byte)-21, (byte)-78, 124, (byte)-88, 52, 117, 34, (byte)-52, (byte)-77, (byte)-107, (byte)-38, (byte)-102, 23, 73, (byte)-76, (byte)-88, 95, 64, (byte)-85, 12, 36, (byte)-86, 86, (byte)-17, 77, 121, 90, 24, (byte)-49, (byte)-107, 33, (byte)-116, 65, 13, 91, 118, (byte)-107, (byte)-21, 65, (byte)-59, 18, 125, 61, (byte)-65, (byte)-68, (byte)-19, 23, 88, 60, (byte)-6, 78, (byte)-8, 69, (byte)-62, (byte)-118, (byte)-93, 97, (byte)-64, (byte)-67, 28, 28, (byte)-87, (byte)-97, 72, (byte)-125, (byte)-119, 4, (byte)-43, 7, 22, (byte)-15, 52, 52, (byte)-82, (byte)-5, (byte)-51, 99, 20, (byte)-59, (byte)-2, (byte)-54, (byte)-67, 40, (byte)-128, (byte)-20, (byte)-37, 50, 123, 32, 8, (byte)-39, (byte)-105, 93, 73, 77, 84, 43, 89, 88, (byte)-6, 7, (byte)-108, 81, 27, 1, 50, 16, (byte)-101, 67, 95, 119, 105, 70, 99, (byte)-127, 22, 127, (byte)-33, (byte)-19, (byte)-113, (byte)-55, (byte)-100, 122, (byte)-86, 98, 53, 27, (byte)-95, 4, (byte)-121, (byte)-96, 87, 67, (byte)-98, (byte)-37, (byte)-10, 92, 29, (byte)-3, (byte)-115, (byte)-23, 37, 8, (byte)-30, 99, (byte)-117, 62, 101, 83, 49, 60, (byte)-83, (byte)-47, (byte)-33, 41, (byte)-118, 76, (byte)-7, 111, (byte)-15, 123, (byte)-59, 53, 2, (byte)-20, (byte)-57, 24, 57, 62, 84, (byte)-26, (byte)-11, 93, (byte)-118, 54, (byte)-13, 56, 77, (byte)-66, 18, (byte)-62, (byte)-76, 80, 98, 26, 120, (byte)-93, 55, 103, (byte)-1, 78, (byte)-92, 120, (byte)-23, (byte)-60, (byte)-75, 11, 53, (byte)-62, (byte)-94, (byte)-80, 120, 113, 33, (byte)-24, (byte)-64, (byte)-5, 23, 120, (byte)-14, 61, 26, (byte)-1, 56, 79, 34, 116, (byte)-16, (byte)-95, (byte)-71, 40, (byte)-89, (byte)-50, 71, (byte)-117, (byte)-109, 2, (byte)-2, (byte)-34, 94, (byte)-78, (byte)-88, (byte)-27, 70, 94, (byte)-86, 123, (byte)-49, 107, (byte)-65, (byte)-67, 84, 90, 123, (byte)-61, (byte)-2, 43, (byte)-119, (byte)-93, 75, (byte)-4, (byte)-81, 98, (byte)-36, 125, (byte)-23, (byte)-37, 81, 104, 90, (byte)-63, (byte)-52, 88, (byte)-96, (byte)-44, 25, 3, (byte)-37, (byte)-123, (byte)-48, 113, (byte)-76, (byte)-94, (byte)-109, (byte)-115, 37, (byte)-39, 104, (byte)-124, 82, (byte)-73, 100, 48, (byte)-54, (byte)-40, (byte)-65, 81, 16, (byte)-85, (byte)-41, 60, 42, 117, 65, 77, 14, (byte)-8, (byte)-56, 52, (byte)-118, (byte)-109, 125, 13, 64, (byte)-20, 125, (byte)-37, (byte)-74, (byte)-28, 118, 112, (byte)-126, 18, (byte)-101, 11, 75, 30, (byte)-4, (byte)-121, (byte)-13, (byte)-65, (byte)-13, (byte)-122, (byte)-53, (byte)-52, 20, (byte)-2, 67, 18, (byte)-106, 67, 83, (byte)-111, 15, 106, 10, 113, 53, (byte)-112, (byte)-3, 118, 8, (byte)-56, 40, 53, 23, (byte)-123, 96, 87, (byte)-118, (byte)-97, (byte)-116, (byte)-47, 85, (byte)-73, (byte)-85, (byte)-82, 124, (byte)-55, 55, 61, 46, 12, (byte)-6, 34, 22, (byte)-22, 3, 115, (byte)-49, 102, 23, 46, 39, 0, 118, 3, (byte)-45, 48, (byte)-73, (byte)-38, 29, (byte)-36, 11, (byte)-127, (byte)-86, 30, 29, (byte)-2, (byte)-108, (byte)-114, 64, 110, 86, (byte)-46, (byte)-91, (byte)-64, 95, (byte)-40, (byte)-65, 49, (byte)-79, (byte)-126, (byte)-37, (byte)-103, (byte)-71, 53, (byte)-85, 45, (byte)-51, 33, (byte)-28, (byte)-126, 36, (byte)-77, (byte)-120, 55, (byte)-54, 72, (byte)-21, 58, (byte)-87, (byte)-73, 18, (byte)-12, 20, (byte)-100, 30, 118, (byte)-83, (byte)-22, (byte)-90, 71, (byte)-64, 108, 101, (byte)-46, 36, 105, (byte)-46, (byte)-91, 60, (byte)-113, 72, 100, 82, (byte)-90, 106, (byte)-127, 65, (byte)-94, 17, 77, (byte)-10, (byte)-112, 46, 118, 72, (byte)-84, 57, (byte)-86, (byte)-114, 88, 91, 79, 30, 107, (byte)-35, 61, 81, 71, 40, (byte)-29, (byte)-6, (byte)-107, 61, (byte)-62, (byte)-6, 65, (byte)-68, 118, 61, 110, (byte)-115, (byte)-119, (byte)-73, 104, 59, (byte)-66, (byte)-89, (byte)-127, (byte)-8, (byte)-67, 122, (byte)-38, 79, (byte)-13, 93, 1, (byte)-32, (byte)-47, (byte)-3, 62, 88, (byte)-112, 105, 73, 96, 73, (byte)-104, (byte)-126, (byte)-69, 21, (byte)-22, 16, (byte)-85, 116, 9, 82, 54, (byte)-15, (byte)-55, (byte)-67, 68, (byte)-23, 16, (byte)-89, 48, (byte)-17, (byte)-107, 60, (byte)-43, (byte)-34, 66, (byte)-114, 63, (byte)-3, (byte)-26, 68, 68, (byte)-86, 120, (byte)-111, 99, 61, 101, 27, 93, 31, 90, (byte)-33, (byte)-94, 29, (byte)-89, 41, (byte)-80, 26, (byte)-23, (byte)-80, 27, 107, 69, (byte)-45, (byte)-123, 62, 63, 80, 1, (byte)-28, 52, (byte)-8, 35, (byte)-86, (byte)-127, 76, 102, 83, (byte)-104, (byte)-79, (byte)-98, 77, (byte)-28, 118, 18, (byte)-15, (byte)-98, (byte)-39, 2, (byte)-58, 95, 64, 105, (byte)-82, (byte)-7, 96, 110, 104, 127, 126, (byte)-124, 26, 36, 33, (byte)-42, 59, 82, 127, 42, (byte)-24, (byte)-61, (byte)-50, (byte)-18, (byte)-87, 22, (byte)-32, (byte)-125, (byte)-70, 103, (byte)-121, (byte)-112, (byte)-94, 58, (byte)-95, (byte)-97, 53, 95, (byte)-61, (byte)-83, 42, 37, 80, 51, (byte)-118, 125, 15, 67, 41, (byte)-97, 41, (byte)-121, 29, (byte)-88, 100, (byte)-113, 39, 101, 47, 91, (byte)-36, 48, (byte)-56, (byte)-13, 12, 37, 0, 81, 3, (byte)-40, 8, 36, (byte)-65, (byte)-11, (byte)-32, 108, 62, 79, 70, 91, (byte)-83, 2, (byte)-47, 0, 91, 10, 87, (byte)-19, (byte)-40, 96, 106, 41, 120, (byte)-53, 40, (byte)-114, 90, 64, 59, (byte)-115, 39, 2, 53, (byte)-49, (byte)-72, (byte)-114, 94, 5, 49, 74, 13, 50, (byte)-14, 76, (byte)-123, (byte)-11, (byte)-81, 100, 120, 16, (byte)-41, (byte)-72, (byte)-118, 28, 41, 98, 122, 27, 18, (byte)-108, (byte)-43, 51, (byte)-71, 93, (byte)-13, (byte)-42, (byte)-64, (byte)-118, (byte)-106, 45, 108, 72, (byte)-128, 58, (byte)-123, (byte)-29, (byte)-114, 15, 52, (byte)-72, 108, (byte)-62, 75, (byte)-15, 105, (byte)-89, 25, 37, 13, (byte)-21, (byte)-109, 68, 5, (byte)-89, 69, 10, (byte)-46, 18, (byte)-57, 77, (byte)-103, (byte)-74, 57, (byte)-43, (byte)-110, 1, (byte)-80, 82, 5, (byte)-9, (byte)-49, (byte)-53, 83, 4, 44, 64, (byte)-117, (byte)-67, (byte)-11, 1, (byte)-65, (byte)-81, 34, (byte)-23, (byte)-71, 14, 105, (byte)-93, 2, (byte)-120, 90, 92, (byte)-6, (byte)-128, (byte)-16, (byte)-51, 27, 123, 71, (byte)-117, (byte)-72, (byte)-81, 26, 28, 5, (byte)-117, (byte)-30, 22, (byte)-72, (byte)-76, (byte)-32, (byte)-14, 82, 90, 69, 74, (byte)-94, (byte)-72, (byte)-30, (byte)-17, 12, (byte)-37, (byte)-3, (byte)-80, 72, 2, (byte)-40, 41, 0, (byte)-53, 48, (byte)-37, (byte)-117, (byte)-128, (byte)-120, (byte)-80, 28, 49, (byte)-52, 114, (byte)-119, 92, (byte)-42, (byte)-105, 125, (byte)-95, 78, 76, 123, (byte)-56, 32, (byte)-66, 69, (byte)-58, 57, (byte)-77, (byte)-100, (byte)-70, 125, 53, (byte)-115, 8, 116, 88, (byte)-34, 86, (byte)-75, 55, 64, 79, (byte)-113, (byte)-124, (byte)-91, 50, (byte)-82, (byte)-119, 50, 11, 87, (byte)-14, (byte)-25, 15, (byte)-1, (byte)-49, (byte)-127, (byte)-5, (byte)-50, 72, (byte)-29, (byte)-78, 101, (byte)-119, (byte)-21, (byte)-15, 97, (byte)-63, 57, (byte)-123, (byte)-94, (byte)-24, (byte)-8, 104, 86, 79, 49, 102, (byte)-8, (byte)-76, 8, 69, 99, (byte)-64, (byte)-108, 70, 36, 71, (byte)-127, 56, 39, 78, 109, 42, (byte)-42, (byte)-2, 126, 17, (byte)-88, (byte)-65, (byte)-23, (byte)-64, 78, 87, 7, 6, (byte)-82, (byte)-98, 41, (byte)-46, (byte)-10, (byte)-25, 90, (byte)-73, 24, 127, (byte)-27, 118, (byte)-9, 81, (byte)-3, 115, (byte)-4, 47, 86, (byte)-30, (byte)-9, (byte)-50, 32, 86, 114, 58, (byte)-5, 78, 74, 36, 29, (byte)-126, 116, 117, (byte)-114, (byte)-92, (byte)-121, (byte)-36, (byte)-86, (byte)-18, 55, 49, 112, 43, 111, (byte)-99, (byte)-116, 70, 60, (byte)-63, 87, (byte)-4, (byte)-35, 15, 28, (byte)-27, (byte)-65, 66, 115, (byte)-33, 112, 94, 74, (byte)-22, 104, (byte)-56, (byte)-27, 39, (byte)-8, (byte)-53, (byte)-120, 8, (byte)-109, 73, (byte)-68, 67, 40, (byte)-59, 59, 121, (byte)-76, (byte)-41, (byte)-80, (byte)-54, (byte)-88, (byte)-120, (byte)-121, (byte)-118, (byte)-58, 74, (byte)-120, 82, (byte)-88, (byte)-113, 30, (byte)-8, 54, (byte)-126, (byte)-106, 37, (byte)-43, (byte)-74, (byte)-56, 40, (byte)-76, 93, 91, 28, (byte)-59, (byte)-30, (byte)-2, 107, 6, (byte)-89, (byte)-69, (byte)-121, (byte)-125, (byte)-109, 5, (byte)-94, (byte)-7, (byte)-2, (byte)-5, (byte)-67, 54, (byte)-90, 39, 5, (byte)-80, 93, (byte)-99, 82, (byte)-100, (byte)-128, (byte)-8, (byte)-39, (byte)-109, 66, (byte)-11, 99, (byte)-41, 18, (byte)-32, (byte)-122, 69, 6, (byte)-95, (byte)-21, 9, 19, (byte)-117, (byte)-34, (byte)-42, 11, 20, 84, 89, 91, (byte)-61, (byte)-13, (byte)-7, 55, 90, (byte)-15, 62, 59, (byte)-4, 125, (byte)-127, (byte)-24, (byte)-124, (byte)-99, (byte)-63, (byte)-23, 52, 111, (byte)-52, (byte)-60, (byte)-113, (byte)-65, (byte)-26, 127, 57, 21, 102, 101, (byte)-77, 66, (byte)-116, 117, 80, 7, 1, (byte)-96, (byte)-29, (byte)-99, 75, (byte)-73, 44, (byte)-99, 61, (byte)-73, 15, (byte)-18, 89, 95, 104, (byte)-12, 94, 33, 13, (byte)-49, 118, (byte)-84, (byte)-122, (byte)-2, (byte)-121, 62, (byte)-32, (byte)-80, 11, (byte)-10, 102, (byte)-67, 20, (byte)-3, 25, (byte)-6, 51, (byte)-17, (byte)-123, (byte)-76, 103, 3, 127, (byte)-107, (byte)-5, 122, 65, 22, 113, 120, 6, (byte)-19, (byte)-110, 86, 55, (byte)-88, (byte)-124, 0, (byte)-54, 17, 112, 15, 105, (byte)-28, 111, (byte)-93, 85, (byte)-59, (byte)-88, 28, 123, 55, 117, 10, 76, 54, (byte)-98, 116, 40, (byte)-65, (byte)-53, (byte)-80, 46, 66, (byte)-8, (byte)-114, 102, 66, 67, (byte)-117, 46, 21, (byte)-116, (byte)-38, 58, (byte)-105, 101, 37, (byte)-16, 5, 55, (byte)-33, (byte)-87, 72, 122, (byte)-114, (byte)-91, 41, (byte)-114, 77, 50, 109, 35, (byte)-61, 9, (byte)-55, (byte)-118, 126, (byte)-35, (byte)-108, 5, 62, 125, (byte)-109, (byte)-115, (byte)-55, 32, (byte)-71, 69, 110, 87, (byte)-82, 119, 26, 103, (byte)-77, (byte)-38, (byte)-13, 113, 74, 69, 116, 94, (byte)-21, 5, 35, 73, (byte)-80, (byte)-87, 80, 13, 108, 1, 82, (byte)-56, (byte)-35, (byte)-21, (byte)-78, (byte)-98, 121, 112, (byte)-117, 72, 47, 76, (byte)-97, (byte)-84, (byte)-110, (byte)-35, (byte)-19, (byte)-120, (byte)-13, 127, 5, 56, 72, (byte)-22, 110, (byte)-8, (byte)-71, 0, (byte)-57, (byte)-125, (byte)-101, 60, (byte)-64, (byte)-32, 1, 126, (byte)-109, 9, 84, 117, 62, (byte)-68, (byte)-106, 28, (byte)-118, (byte)-52, (byte)-81, 112, 11, 55, 68, (byte)-86, (byte)-65, 123, 83, 55, (byte)-72, 110, 63, (byte)-90, 31, 11, 90, (byte)-60, 20, 14, (byte)-36, 5, (byte)-92, 11, (byte)-100, 64, (byte)-57, (byte)-72, (byte)-105, 7, 103, 125, 99, (byte)-88, 32, (byte)-5, 41, (byte)-115, (byte)-11, 89, 81, 77, (byte)-33, (byte)-7, (byte)-123, (byte)-17, 109, 59, 40, (byte)-12, (byte)-61, 98, (byte)-91, 19, (byte)-36, 108, 118, (byte)-124, (byte)-82, (byte)-40, (byte)-124, (byte)-66, 19, 127, (byte)-73, (byte)-39, 99, 43, (byte)-16, (byte)-44, (byte)-83, (byte)-77, (byte)-34, 68, (byte)-118, (byte)-71, (byte)-116, 114, 120, (byte)-34, (byte)-105, (byte)-32, (byte)-46, 102, 73, (byte)-79, 7, 42, 35, (byte)-66, 125, 34, 113, 66, 78, 71, 6, 44, (byte)-17, 4, (byte)-80, 38, (byte)-59, 12, (byte)-8, (byte)-78, 103, 8, 80, 18, (byte)-74, 20, 3, 56, (byte)-20, 106, (byte)-1, (byte)-12, 83, 4, 68, (byte)-119, 84, (byte)-87, 97, (byte)-53, 102, 119, 34, (byte)-85, 22, (byte)-26, 55, (byte)-107, 96, (byte)-70, 77, (byte)-68, (byte)-96, (byte)-15, (byte)-22, (byte)-77, (byte)-55, 5, 103, (byte)-42, (byte)-87, 122, (byte)-80, (byte)-103, (byte)-37, (byte)-120, (byte)-56, (byte)-16, (byte)-51, (byte)-7, (byte)-19, (byte)-104, 120, 9, 54, (byte)-85, 48, (byte)-76, (byte)-38, 58, (byte)-68, 116, (byte)-20, (byte)-44, 22, (byte)-32, 75, (byte)-46, (byte)-41, 13, (byte)-100, 16, (byte)-59, (byte)-93, (byte)-115, 54, 22, (byte)-110, (byte)-46, (byte)-119, 44, (byte)-98, (byte)-48, 4, (byte)-58, (byte)-115, (byte)-57, 103, (byte)-56, 36, (byte)-63, 104, (byte)-114, (byte)-125, 92, 65, 117, (byte)-21, (byte)-59, (byte)-31, 56, (byte)-98, (byte)-126, 56, 47, (byte)-116, 100, 122, (byte)-98, 4, 26, (byte)-29, (byte)-127, (byte)-113, 73, 48, 106, 125, (byte)-69, (byte)-127, 62, 56, (byte)-79, 76, 84, (byte)-46, (byte)-31, (byte)-17, 94, (byte)-98, 62, 63, 118, (byte)-24, 63, 123, (byte)-93, (byte)-46, 103, 117, (byte)-120, (byte)-35, 19, 25, 15, (byte)-110, (byte)-125, 12, (byte)-75, (byte)-50, 103, 49, 47, 98, 92, 10, (byte)-88, 54, (byte)-53, 19, 25, (byte)-90, 93, (byte)-49, 64, 126, (byte)-106, (byte)-30, (byte)-52, 58, 37, 68, (byte)-18, (byte)-60, 15, (byte)-27, 93, (byte)-124, 88, 110, (byte)-80, (byte)-106, 88, 55, 108, (byte)-58, (byte)-43, (byte)-70, 76, 85, 98, 27, (byte)-66, 18, 75, 69, 114, 90, (byte)-26, (byte)-10, (byte)-12, (byte)-126, 84, (byte)-109, 108, 15, (byte)-115, 90, 11, (byte)-127, 63, (byte)-7, 47, 92, (byte)-72, 38, (byte)-58, (byte)-35, 18, 25, 12, (byte)-103, 0};

			fullBytes = new byte[pubBytes.Length + privBytes.Length];

			JavaSystem.arraycopy(pubBytes, 0, fullBytes, 0, pubBytes.Length);
			JavaSystem.arraycopy(privBytes, 0, fullBytes, pubBytes.Length, privBytes.Length);

			priv = new NTRUEncryptionPrivateKeyParameters(fullBytes, @params.getEncryptionParameters());
			pub = new NTRUEncryptionPublicKeyParameters(pubBytes, @params.getEncryptionParameters());
			kp = new AsymmetricCipherKeyPair(pub, priv);
			ntru.init(true, kp.getPublic());

			encrypted = ntru.processBlock(plainText, 0, plainText.Length);

			ntru.init(false, kp.getPrivate());

			decrypted = ntru.processBlock(encrypted, 0, encrypted.Length);

			assertTrue(Arrays.areEqual(plainText, decrypted));
		}

		// encrypts and decrypts text using an encoded key pair (fastFp=true)
		public virtual void testEncodedKeysFast()
		{
			byte[] plainText = "secret encrypted text".GetBytes();

			NTRUEncryptionKeyGenerationParameters @params = NTRUEncryptionKeyGenerationParameters.APR2011_743_FAST;
			NTRUEngine ntru = new NTRUEngine();
			byte[] privBytes = new byte[] {10, 16, 2, 30, -40, -63, -109, -77, -72, -122, 66, 23, -30, -44, -82, 0, 95, 64, 68, 48, -62, -14, 26, -19, -72, -25, 72, 123, 98, 84, -83, 0, 7, 40, 65, 35, 68, 113, 12, -112, 32, -123, 58, 85, -30, -109, -74, 0, 34, -8, -126, 57, 30, 98, -107, -45, -88, 102, 68, 42, -30, -108, -89, 0, 38, -40, -61, 37, 82, 113, -115, 123, -100, 5, 46, 125, -23, 78, -111, -76, 36, -90, 67, -31, 10, 2, 96, -127, 21, 50, -79, 13, -125, -124, 38, 55, -67, -95, 81, -107, 12, 117, -86, 99, -127, 11};
			byte[] pubBytes = new byte[] {108, -76, -104, -75, -87, -65, -18, -5, 45, -57, -100, -83, 51, 99, 94, 15, -73, 89, -100, 40, -114, 91, -107, 104, 127, 22, 13, 5, -16, 69, -104, -126, -44, 119, 47, -48, 75, 66, 83, -37, -66, -84, 73, 52, 23, -27, 53, 63, 56, 14, -2, 43, -59, -85, -80, 46, 38, -126, 75, -8, -63, 88, 104, 13, 72, -25, -10, -58, -51, 117, -84, 115, -24, -53, 83, -103, -97, 46, 90, -82, -61, 113, -49, -24, -72, 24, -124, -42, -36, 7, 41, 8, 14, -71, -75, -84, -24, -39, 56, 67, 88, 67, 66, -13, 70, -119, -64, 74, -100, -58, 35, 105, -20, 93, 80, -116, -55, 37, -52, 64, 0, -36, -71, 8, 77, -10, -41, -22, -73, 4, -115, -74, -74, -73, 23, -10, -26, 48, 125, -114, -32, -116, 74, 19, -104, 59, 43, 4, 97, -84, 112, 45, 16, 3, -110, -13, 119, -6, 29, -80, 109, 82, -31, 82, 30, 76, -111, -122, -50, -69, -41, -123, 107, 78, -35, 24, -121, -87, -108, 13, 70, 32, -74, 112, 104, -40, -61, 86, -125, 60, -94, -5, -18, 55, 54, -128, 83, -88, 71, 71, -66, 29, -113, 120, 30, 16, -38, 37, 96, -90, 38, -85, 88, 59, 15, -69, 6, -8, 1, 1, 71, 12, 60, -26, -110, 97, 77, 33, 58, 63, 104, 108, 83, 72, -21, -99, 115, -125, -16, 12, 99, 68, 39, -97, -6, 17, 26, -59, 123, -110, -37, -71, 47, 50, 5, 110, -34, 89, -74, 20, 79, -108, -7, 42, 106, -112, 44, 107, 106, -50, 55, 127, -124, 53, 123, -119, -46, -114, -52, -85, 75, 34, -39, -125, 58, -5, -31, -81, -37, -94, -123, 113, 11, -104, -124, 96, -103, 9, 108, 115, 97, -6, 98, -43, 26, -89, -23, 83, 60, 34, -86, -54, 107, 78, -48, 118, -31, -19, 29, -106, 108, 117, 83, 119, 51, -45, 115, 108, -13, -89, -29, 29, -120, 108, 20, 22, -3, 22, 78, -109, 95, 3, -68, -10, -53, -117, -96, -49, 9, 7, 38, 116, 33, -65, 31, 9, -5, -73, 127, 52, 113, 87, -39, 119, -96, 74, -105, 75, -89, 63, 69, -109, -127, 92, -54, 17, -98, -23, -69, 123, -125, 23, -93, 44, -11, -25, -101, 120, -29, 113, -33, 0, -117, -100, -114, 22, 41, -46, 29, -109, 107, 37, -94, 125, 46, 17, 16, -65, -14, 105, -118, 51, -21, 121, -5, 56, 29, 30, -69, -38, -10, -77, -74, 6, -105, 83, 110, 23, 114, -11, -123, -14, 30, -11, -9, 84, -90, -20, -29, 72, -85, 97, -74, -59, -112, -15, -51, -105, 117, 123, -17, -64, -127, 127, -33, -102, 88, 77, 122, -127, -15, 121, -125, -32, 53, 113, 45, -22, 84, -87, 20, 36, 65, 83, -84, -66, -22, 4, 15, -108, -92, 109, -128, -48, 4, -27, -13, 25, 51, -10, 34, 87, 88, 38, -87, 89, -64, -62, 20, 78, 35, -26, -2, 55, 3, -72, -64, 30, 28, -105, 6, -37, -38, -8, 26, -118, 105, -37, -30, 85, -66, 105, -46, -37, -11, -72, 71, 43, -65, -44, 17, -79, 98, 79, -77, -111, 95, 74, 101, -40, -106, 14, -108, -112, 86, 108, 49, 72, -38, -103, -31, 65, -119, 8, 78, -89, 100, -28, 116, 94, 15, -18, 108, 101, 85, 8, -6, 111, -82, -49, -66, -89, 28, -84, -85, -119, 111, 45, 83, -60, -40, -45, -101, -105, -35, 123, -1, 13, -112, 79, -80, -85, -109, -71, 69, 104, 95, -93, 121, -17, 83, 117, -73, -63, -65, -107, -72, 118, -102, -56, 38, 79, 121, -25, -86, -81, -38, 8, 122, 97, 37, 82, -40, 53, 11, 124, -94, -76, -107, -125, -9, -119, 63, 52, -34, -72, -21, 59, 3, -100, -127, 47, -102, 19, -37, -45, -114, -65, 39, -106, 6, -127, -110, -38, 96, -38, -51, 110, -3, 28, 8, 102, -102, 96, -127, 109, -56, -53, -13, 59, -98, 92, 80, 1, 55, -91, -122, -105, 28, 69, -85, 109, -38, 105, 87, -5, 3, -102, 62, -92, 60, 43, -20, -7, -23, -84, 106, 121, -48, 123, -112, 56, -17, -52, 14, -123, -122, 64, 14, -23, -71, 60, 70, -121, 6, 37, -15, 77, 96, 104, -34, 58, -125, -61, 1, -26, 118, -78, -35, -1, 0, 5, 33, -98, -86, -127, 25, 56, -91, 82, -33, 60, -64, -86, 27, 31, -80, -79, 118, -12, -18, 40, -72, 32, 119, -28, -62, 100, -121, -71, -79, -9, 38, -37, 25, 65, -46, 8, -112, 37, 9, -56, 123, -40, -44, -90, -21, -54, -2, -7, 107, -93, 24, -126, 69, 42, -111, -84, 57, 69, -119, 21, 60, 57, -122, 111, -99, 49, -46, -119, 100, 98, 24, -62, 112, 122, 46, 18, -35, -67, 89, 104, 82, 12, 125, 57, -70, -112, -109, 96, 51, -68, 1, -101, -59, -92, 54, 85, -41, 17, 31, 94, 75, -128, 53, 84, 0, -83, -94, -123, 49, -30, -24, 18, 46, 48, -33, 120, 66, -69, 70, 23, -124, -117, 81, 96, 46, 47, -33, 83, -13, -14, -94, 49, 66, -46, 84, -27, -77, 6, 0, -75, -18, 86, -119, -88, 82, -50, 55, -20, 63, 55, -57, 22, -108, -103, -17, -22, 64, 65, 90, -34, -96, -117, 51, 119, -103, -35, 95, -15, -118, 2, -31, 31, -9, -58, 84, -75, 80, 39, -101, -56, 16, -75, 59, 48, -63, -24, -95, 119, 73, -110, -115, 49, -18, 54, -124, 112, -61, -40, -105, -118, -66, 15, -107, 75, 82, -70, -87, -11, -11, 48, 41, 119, -42, -34, -33, 57, 23, -14, -45, -125, -108, -75, 3, 44, 44, 58, 126, -126, -20, -123, 58, 114, 79, -102, -115, 115, 12, 66, 108, 84, 43, -46, -80, -41, -70, 111, -114, 123, 21, 1, 34, -72, 23, 105, -52, -39, -54, -119, 45, 77, -16, -66, -105, -11, 91, -46, 77, -104, -93, 52, -3, 17, 55, -10, 67, -33, 43, 75, -103, 106, 7, -35, -65, -21, 68, 118, -38, 59, -115, 31};

			byte[] fullBytes = new byte[pubBytes.Length + privBytes.Length];

			JavaSystem.arraycopy(pubBytes, 0, fullBytes, 0, pubBytes.Length);
			JavaSystem.arraycopy(privBytes, 0, fullBytes, pubBytes.Length, privBytes.Length);

			NTRUEncryptionPrivateKeyParameters priv = new NTRUEncryptionPrivateKeyParameters(fullBytes, @params.getEncryptionParameters());
			NTRUEncryptionPublicKeyParameters pub = new NTRUEncryptionPublicKeyParameters(pubBytes, @params.getEncryptionParameters());
			AsymmetricCipherKeyPair kp = new AsymmetricCipherKeyPair(pub, priv);

			ntru.init(true, kp.getPublic());

			byte[] encrypted = ntru.processBlock(plainText, 0, plainText.Length);

			assertEquals(encrypted.Length, ntru.getOutputBlockSize());

			ntru.init(false, kp.getPrivate());

			byte[] decrypted = ntru.processBlock(encrypted, 0, encrypted.Length);

			assertTrue(Arrays.areEqual(plainText, decrypted));
		}

		public class VisibleNTRUEngine : NTRUEngine
		{
			private readonly NTRUEncryptTest outerInstance;

			public VisibleNTRUEngine(NTRUEncryptTest outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public override IntegerPolynomial encrypt(IntegerPolynomial m, TernaryPolynomial r, IntegerPolynomial pubKey)
			{
				return base.encrypt(m, r, pubKey);
			}

			public override IntegerPolynomial decrypt(IntegerPolynomial e, Polynomial priv_t, IntegerPolynomial priv_fp)
			{
				return base.decrypt(e, priv_t, priv_fp);
			}
		}
	}

}