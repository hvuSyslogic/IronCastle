using org.bouncycastle.bcpg;

using System;

namespace org.bouncycastle.gpg
{

	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using DSAPublicBCPGKey = org.bouncycastle.bcpg.DSAPublicBCPGKey;
	using DSASecretBCPGKey = org.bouncycastle.bcpg.DSASecretBCPGKey;
	using ECDSAPublicBCPGKey = org.bouncycastle.bcpg.ECDSAPublicBCPGKey;
	using ECPublicBCPGKey = org.bouncycastle.bcpg.ECPublicBCPGKey;
	using ECSecretBCPGKey = org.bouncycastle.bcpg.ECSecretBCPGKey;
	using ElGamalPublicBCPGKey = org.bouncycastle.bcpg.ElGamalPublicBCPGKey;
	using ElGamalSecretBCPGKey = org.bouncycastle.bcpg.ElGamalSecretBCPGKey;
	using HashAlgorithmTags = org.bouncycastle.bcpg.HashAlgorithmTags;
	using PublicKeyAlgorithmTags = org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
	using PublicKeyPacket = org.bouncycastle.bcpg.PublicKeyPacket;
	using RSAPublicBCPGKey = org.bouncycastle.bcpg.RSAPublicBCPGKey;
	using RSASecretBCPGKey = org.bouncycastle.bcpg.RSASecretBCPGKey;
	using S2K = org.bouncycastle.bcpg.S2K;
	using SecretKeyPacket = org.bouncycastle.bcpg.SecretKeyPacket;
	using SymmetricKeyAlgorithmTags = org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
	using PGPException = org.bouncycastle.openpgp.PGPException;
	using PGPPublicKey = org.bouncycastle.openpgp.PGPPublicKey;
	using PGPSecretKey = org.bouncycastle.openpgp.PGPSecretKey;
	using KeyFingerPrintCalculator = org.bouncycastle.openpgp.@operator.KeyFingerPrintCalculator;
	using PBEProtectionRemoverFactory = org.bouncycastle.openpgp.@operator.PBEProtectionRemoverFactory;
	using PBESecretKeyDecryptor = org.bouncycastle.openpgp.@operator.PBESecretKeyDecryptor;
	using PGPDigestCalculator = org.bouncycastle.openpgp.@operator.PGPDigestCalculator;
	using PGPDigestCalculatorProvider = org.bouncycastle.openpgp.@operator.PGPDigestCalculatorProvider;
	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// A parser for secret keys stored in SExpr
	/// </summary>
	public class SExprParser
	{
		private readonly PGPDigestCalculatorProvider digestProvider;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="digestProvider"> a provider for digest calculations. Used to confirm key protection hashes. </param>
		public SExprParser(PGPDigestCalculatorProvider digestProvider)
		{
			this.digestProvider = digestProvider;
		}

		/// <summary>
		/// Parse a secret key from one of the GPG S expression keys associating it with the passed in public key.
		/// </summary>
		/// <returns> a secret key object. </returns>
		public virtual PGPSecretKey parseSecretKey(InputStream inputStream, PBEProtectionRemoverFactory keyProtectionRemoverFactory, PGPPublicKey pubKey)
		{
			SXprUtils.skipOpenParenthesis(inputStream);

			string type;

			type = SXprUtils.readString(inputStream, inputStream.read());
			if (type.Equals("protected-private-key"))
			{
				SXprUtils.skipOpenParenthesis(inputStream);

				string keyType = SXprUtils.readString(inputStream, inputStream.read());
				if (keyType.Equals("ecc"))
				{
					SXprUtils.skipOpenParenthesis(inputStream);

					string curveID = SXprUtils.readString(inputStream, inputStream.read());
					string curveName = SXprUtils.readString(inputStream, inputStream.read());

					SXprUtils.skipCloseParenthesis(inputStream);

					byte[] qVal;

					SXprUtils.skipOpenParenthesis(inputStream);

					type = SXprUtils.readString(inputStream, inputStream.read());
					if (type.Equals("q"))
					{
						qVal = SXprUtils.readBytes(inputStream, inputStream.read());
					}
					else
					{
						throw new PGPException("no q value found");
					}

					SXprUtils.skipCloseParenthesis(inputStream);

					BigInteger d = processECSecretKey(inputStream, curveID, curveName, qVal, keyProtectionRemoverFactory);

					if (curveName.StartsWith("NIST ", StringComparison.Ordinal))
					{
						curveName = curveName.Substring("NIST ".Length);
					}

					ECPublicBCPGKey basePubKey = new ECDSAPublicBCPGKey(ECNamedCurveTable.getOID(curveName), new BigInteger(1, qVal));
					ECPublicBCPGKey assocPubKey = (ECPublicBCPGKey)pubKey.getPublicKeyPacket().getKey();
					if (!basePubKey.getCurveOID().Equals(assocPubKey.getCurveOID()) || !basePubKey.getEncodedPoint().Equals(assocPubKey.getEncodedPoint()))
					{
						throw new PGPException("passed in public key does not match secret key");
					}

					return new PGPSecretKey(new SecretKeyPacket(pubKey.getPublicKeyPacket(), SymmetricKeyAlgorithmTags_Fields.NULL, null, null, (new ECSecretBCPGKey(d)).getEncoded()), pubKey);
				}
				else if (keyType.Equals("dsa"))
				{
					BigInteger p = readBigInteger("p", inputStream);
					BigInteger q = readBigInteger("q", inputStream);
					BigInteger g = readBigInteger("g", inputStream);

					BigInteger y = readBigInteger("y", inputStream);

					BigInteger x = processDSASecretKey(inputStream, p, q, g, y, keyProtectionRemoverFactory);

					DSAPublicBCPGKey basePubKey = new DSAPublicBCPGKey(p, q, g, y);
					DSAPublicBCPGKey assocPubKey = (DSAPublicBCPGKey)pubKey.getPublicKeyPacket().getKey();
					if (!basePubKey.getP().Equals(assocPubKey.getP()) || !basePubKey.getQ().Equals(assocPubKey.getQ()) || !basePubKey.getG().Equals(assocPubKey.getG()) || !basePubKey.getY().Equals(assocPubKey.getY()))
					{
						throw new PGPException("passed in public key does not match secret key");
					}
					return new PGPSecretKey(new SecretKeyPacket(pubKey.getPublicKeyPacket(), SymmetricKeyAlgorithmTags_Fields.NULL, null, null, (new DSASecretBCPGKey(x)).getEncoded()), pubKey);
				}
				else if (keyType.Equals("elg"))
				{
					BigInteger p = readBigInteger("p", inputStream);
					BigInteger g = readBigInteger("g", inputStream);

					BigInteger y = readBigInteger("y", inputStream);

					BigInteger x = processElGamalSecretKey(inputStream, p, g, y, keyProtectionRemoverFactory);

					ElGamalPublicBCPGKey basePubKey = new ElGamalPublicBCPGKey(p, g, y);
					ElGamalPublicBCPGKey assocPubKey = (ElGamalPublicBCPGKey)pubKey.getPublicKeyPacket().getKey();
					if (!basePubKey.getP().Equals(assocPubKey.getP()) || !basePubKey.getG().Equals(assocPubKey.getG()) || !basePubKey.getY().Equals(assocPubKey.getY()))
					{
						throw new PGPException("passed in public key does not match secret key");
					}

					return new PGPSecretKey(new SecretKeyPacket(pubKey.getPublicKeyPacket(), SymmetricKeyAlgorithmTags_Fields.NULL, null, null, (new ElGamalSecretBCPGKey(x)).getEncoded()), pubKey);
				}
				else if (keyType.Equals("rsa"))
				{
					BigInteger n = readBigInteger("n", inputStream);
					BigInteger e = readBigInteger("e", inputStream);

					BigInteger[] values = processRSASecretKey(inputStream, n, e, keyProtectionRemoverFactory);

					// TODO: type of RSA key?
					RSAPublicBCPGKey basePubKey = new RSAPublicBCPGKey(n, e);
					RSAPublicBCPGKey assocPubKey = (RSAPublicBCPGKey)pubKey.getPublicKeyPacket().getKey();
					if (!basePubKey.getModulus().Equals(assocPubKey.getModulus()) || !basePubKey.getPublicExponent().Equals(assocPubKey.getPublicExponent()))
					{
						throw new PGPException("passed in public key does not match secret key");
					}

					return new PGPSecretKey(new SecretKeyPacket(pubKey.getPublicKeyPacket(), SymmetricKeyAlgorithmTags_Fields.NULL, null, null, (new RSASecretBCPGKey(values[0], values[1], values[2])).getEncoded()), pubKey);
				}
				else
				{
					throw new PGPException("unknown key type: " + keyType);
				}
			}

			throw new PGPException("unknown key type found");
		}

		/// <summary>
		/// Parse a secret key from one of the GPG S expression keys.
		/// </summary>
		/// <returns> a secret key object. </returns>
		public virtual PGPSecretKey parseSecretKey(InputStream inputStream, PBEProtectionRemoverFactory keyProtectionRemoverFactory, KeyFingerPrintCalculator fingerPrintCalculator)
		{
			SXprUtils.skipOpenParenthesis(inputStream);

			string type;

			type = SXprUtils.readString(inputStream, inputStream.read());
			if (type.Equals("protected-private-key"))
			{
				SXprUtils.skipOpenParenthesis(inputStream);

				string keyType = SXprUtils.readString(inputStream, inputStream.read());
				if (keyType.Equals("ecc"))
				{
					SXprUtils.skipOpenParenthesis(inputStream);

					string curveID = SXprUtils.readString(inputStream, inputStream.read());
					string curveName = SXprUtils.readString(inputStream, inputStream.read());

					if (curveName.StartsWith("NIST ", StringComparison.Ordinal))
					{
						curveName = curveName.Substring("NIST ".Length);
					}

					SXprUtils.skipCloseParenthesis(inputStream);

					byte[] qVal;

					SXprUtils.skipOpenParenthesis(inputStream);

					type = SXprUtils.readString(inputStream, inputStream.read());
					if (type.Equals("q"))
					{
						qVal = SXprUtils.readBytes(inputStream, inputStream.read());
					}
					else
					{
						throw new PGPException("no q value found");
					}

					PublicKeyPacket pubPacket = new PublicKeyPacket(PublicKeyAlgorithmTags_Fields.ECDSA, DateTime.Now, new ECDSAPublicBCPGKey(ECNamedCurveTable.getOID(curveName), new BigInteger(1, qVal)));

					SXprUtils.skipCloseParenthesis(inputStream);

					BigInteger d = processECSecretKey(inputStream, curveID, curveName, qVal, keyProtectionRemoverFactory);

					return new PGPSecretKey(new SecretKeyPacket(pubPacket, SymmetricKeyAlgorithmTags_Fields.NULL, null, null, (new ECSecretBCPGKey(d)).getEncoded()), new PGPPublicKey(pubPacket, fingerPrintCalculator));
				}
				else if (keyType.Equals("dsa"))
				{
					BigInteger p = readBigInteger("p", inputStream);
					BigInteger q = readBigInteger("q", inputStream);
					BigInteger g = readBigInteger("g", inputStream);

					BigInteger y = readBigInteger("y", inputStream);

					BigInteger x = processDSASecretKey(inputStream, p, q, g, y, keyProtectionRemoverFactory);

					PublicKeyPacket pubPacket = new PublicKeyPacket(PublicKeyAlgorithmTags_Fields.DSA, DateTime.Now, new DSAPublicBCPGKey(p, q, g, y));

					return new PGPSecretKey(new SecretKeyPacket(pubPacket, SymmetricKeyAlgorithmTags_Fields.NULL, null, null, (new DSASecretBCPGKey(x)).getEncoded()), new PGPPublicKey(pubPacket, fingerPrintCalculator));
				}
				else if (keyType.Equals("elg"))
				{
					BigInteger p = readBigInteger("p", inputStream);
					BigInteger g = readBigInteger("g", inputStream);

					BigInteger y = readBigInteger("y", inputStream);

					BigInteger x = processElGamalSecretKey(inputStream, p, g, y, keyProtectionRemoverFactory);

					PublicKeyPacket pubPacket = new PublicKeyPacket(PublicKeyAlgorithmTags_Fields.ELGAMAL_ENCRYPT, DateTime.Now, new ElGamalPublicBCPGKey(p, g, y));

					return new PGPSecretKey(new SecretKeyPacket(pubPacket, SymmetricKeyAlgorithmTags_Fields.NULL, null, null, (new ElGamalSecretBCPGKey(x)).getEncoded()), new PGPPublicKey(pubPacket, fingerPrintCalculator));
				}
				else if (keyType.Equals("rsa"))
				{
					BigInteger n = readBigInteger("n", inputStream);
					BigInteger e = readBigInteger("e", inputStream);

					BigInteger[] values = processRSASecretKey(inputStream, n, e, keyProtectionRemoverFactory);

					// TODO: type of RSA key?
					PublicKeyPacket pubPacket = new PublicKeyPacket(PublicKeyAlgorithmTags_Fields.RSA_GENERAL, DateTime.Now, new RSAPublicBCPGKey(n, e));

					return new PGPSecretKey(new SecretKeyPacket(pubPacket, SymmetricKeyAlgorithmTags_Fields.NULL, null, null, (new RSASecretBCPGKey(values[0], values[1], values[2])).getEncoded()), new PGPPublicKey(pubPacket, fingerPrintCalculator));
				}
				else
				{
					throw new PGPException("unknown key type: " + keyType);
				}
			}

			throw new PGPException("unknown key type found");
		}

		private BigInteger readBigInteger(string expectedType, InputStream inputStream)
		{
			SXprUtils.skipOpenParenthesis(inputStream);

			string type = SXprUtils.readString(inputStream, inputStream.read());
			if (!type.Equals(expectedType))
			{
				throw new PGPException(expectedType + " value expected");
			}

			byte[] nBytes = SXprUtils.readBytes(inputStream, inputStream.read());
			BigInteger v = new BigInteger(1, nBytes);

			SXprUtils.skipCloseParenthesis(inputStream);

			return v;
		}

		private static byte[][] extractData(InputStream inputStream, PBEProtectionRemoverFactory keyProtectionRemoverFactory)
		{
			byte[] data;
			byte[] protectedAt = null;

			SXprUtils.skipOpenParenthesis(inputStream);

			string type = SXprUtils.readString(inputStream, inputStream.read());
			if (type.Equals("protected"))
			{
				string protection = SXprUtils.readString(inputStream, inputStream.read());

				SXprUtils.skipOpenParenthesis(inputStream);

				S2K s2k = SXprUtils.parseS2K(inputStream);

				byte[] iv = SXprUtils.readBytes(inputStream, inputStream.read());

				SXprUtils.skipCloseParenthesis(inputStream);

				byte[] secKeyData = SXprUtils.readBytes(inputStream, inputStream.read());

				SXprUtils.skipCloseParenthesis(inputStream);

				PBESecretKeyDecryptor keyDecryptor = keyProtectionRemoverFactory.createDecryptor(protection);

				// TODO: recognise other algorithms
				byte[] key = keyDecryptor.makeKeyFromPassPhrase(SymmetricKeyAlgorithmTags_Fields.AES_128, s2k);

				data = keyDecryptor.recoverKeyData(SymmetricKeyAlgorithmTags_Fields.AES_128, key, iv, secKeyData, 0, secKeyData.Length);

				// check if protected at is present
				if (inputStream.read() == '(')
				{
					ByteArrayOutputStream bOut = new ByteArrayOutputStream();

					bOut.write('(');
					int ch;
					while ((ch = inputStream.read()) >= 0 && ch != ')')
					{
						bOut.write(ch);
					}

					if (ch != ')')
					{
						throw new IOException("unexpected end to SExpr");
					}

					bOut.write(')');

					protectedAt = bOut.toByteArray();
				}

				SXprUtils.skipCloseParenthesis(inputStream);
				SXprUtils.skipCloseParenthesis(inputStream);
			}
			else
			{
				throw new PGPException("protected block not found");
			}

			return new byte[][]{data, protectedAt};
		}

		private BigInteger processDSASecretKey(InputStream inputStream, BigInteger p, BigInteger q, BigInteger g, BigInteger y, PBEProtectionRemoverFactory keyProtectionRemoverFactory)
		{
			string type;
			byte[][] basicData = extractData(inputStream, keyProtectionRemoverFactory);

			byte[] keyData = basicData[0];
			byte[] protectedAt = basicData[1];

			//
			// parse the secret key S-expr
			//
			InputStream keyIn = new ByteArrayInputStream(keyData);

			SXprUtils.skipOpenParenthesis(keyIn);
			SXprUtils.skipOpenParenthesis(keyIn);

			BigInteger x = readBigInteger("x", keyIn);

			SXprUtils.skipCloseParenthesis(keyIn);

			SXprUtils.skipOpenParenthesis(keyIn);
			type = SXprUtils.readString(keyIn, keyIn.read());

			if (!type.Equals("hash"))
			{
				throw new PGPException("hash keyword expected");
			}
			type = SXprUtils.readString(keyIn, keyIn.read());

			if (!type.Equals("sha1"))
			{
				throw new PGPException("hash keyword expected");
			}

			byte[] hashBytes = SXprUtils.readBytes(keyIn, keyIn.read());

			SXprUtils.skipCloseParenthesis(keyIn);

			if (digestProvider != null)
			{
				PGPDigestCalculator digestCalculator = digestProvider.get(HashAlgorithmTags_Fields.SHA1);

				OutputStream dOut = digestCalculator.getOutputStream();

				dOut.write(Strings.toByteArray("(3:dsa"));
				writeCanonical(dOut, "p", p);
				writeCanonical(dOut, "q", q);
				writeCanonical(dOut, "g", g);
				writeCanonical(dOut, "y", y);
				writeCanonical(dOut, "x", x);

				// check protected-at
				if (protectedAt != null)
				{
					dOut.write(protectedAt);
				}

				dOut.write(Strings.toByteArray(")"));

				byte[] check = digestCalculator.getDigest();
				if (!Arrays.constantTimeAreEqual(check, hashBytes))
				{
					throw new PGPException("checksum on protected data failed in SExpr");
				}
			}

			return x;
		}

		private BigInteger processElGamalSecretKey(InputStream inputStream, BigInteger p, BigInteger g, BigInteger y, PBEProtectionRemoverFactory keyProtectionRemoverFactory)
		{
			string type;
			byte[][] basicData = extractData(inputStream, keyProtectionRemoverFactory);

			byte[] keyData = basicData[0];
			byte[] protectedAt = basicData[1];

			//
			// parse the secret key S-expr
			//
			InputStream keyIn = new ByteArrayInputStream(keyData);

			SXprUtils.skipOpenParenthesis(keyIn);
			SXprUtils.skipOpenParenthesis(keyIn);

			BigInteger x = readBigInteger("x", keyIn);

			SXprUtils.skipCloseParenthesis(keyIn);

			SXprUtils.skipOpenParenthesis(keyIn);
			type = SXprUtils.readString(keyIn, keyIn.read());

			if (!type.Equals("hash"))
			{
				throw new PGPException("hash keyword expected");
			}
			type = SXprUtils.readString(keyIn, keyIn.read());

			if (!type.Equals("sha1"))
			{
				throw new PGPException("hash keyword expected");
			}

			byte[] hashBytes = SXprUtils.readBytes(keyIn, keyIn.read());

			SXprUtils.skipCloseParenthesis(keyIn);

			if (digestProvider != null)
			{
				PGPDigestCalculator digestCalculator = digestProvider.get(HashAlgorithmTags_Fields.SHA1);

				OutputStream dOut = digestCalculator.getOutputStream();

				dOut.write(Strings.toByteArray("(3:elg"));
				writeCanonical(dOut, "p", p);
				writeCanonical(dOut, "g", g);
				writeCanonical(dOut, "y", y);
				writeCanonical(dOut, "x", x);

				// check protected-at
				if (protectedAt != null)
				{
					dOut.write(protectedAt);
				}

				dOut.write(Strings.toByteArray(")"));

				byte[] check = digestCalculator.getDigest();
				if (!Arrays.constantTimeAreEqual(check, hashBytes))
				{
					throw new PGPException("checksum on protected data failed in SExpr");
				}
			}

			return x;
		}

		private BigInteger processECSecretKey(InputStream inputStream, string curveID, string curveName, byte[] qVal, PBEProtectionRemoverFactory keyProtectionRemoverFactory)
		{
			string type;

			byte[][] basicData = extractData(inputStream, keyProtectionRemoverFactory);

			byte[] keyData = basicData[0];
			byte[] protectedAt = basicData[1];

			//
			// parse the secret key S-expr
			//
			InputStream keyIn = new ByteArrayInputStream(keyData);

			SXprUtils.skipOpenParenthesis(keyIn);
			SXprUtils.skipOpenParenthesis(keyIn);
			BigInteger d = readBigInteger("d", keyIn);
			SXprUtils.skipCloseParenthesis(keyIn);

			SXprUtils.skipOpenParenthesis(keyIn);

			type = SXprUtils.readString(keyIn, keyIn.read());

			if (!type.Equals("hash"))
			{
				throw new PGPException("hash keyword expected");
			}
			type = SXprUtils.readString(keyIn, keyIn.read());

			if (!type.Equals("sha1"))
			{
				throw new PGPException("hash keyword expected");
			}

			byte[] hashBytes = SXprUtils.readBytes(keyIn, keyIn.read());

			SXprUtils.skipCloseParenthesis(keyIn);

			if (digestProvider != null)
			{
				PGPDigestCalculator digestCalculator = digestProvider.get(HashAlgorithmTags_Fields.SHA1);

				OutputStream dOut = digestCalculator.getOutputStream();

				dOut.write(Strings.toByteArray("(3:ecc"));

				dOut.write(Strings.toByteArray("(" + curveID.Length + ":" + curveID + curveName.Length + ":" + curveName + ")"));

				writeCanonical(dOut, "q", qVal);
				writeCanonical(dOut, "d", d);

				// check protected-at
				if (protectedAt != null)
				{
					dOut.write(protectedAt);
				}

				dOut.write(Strings.toByteArray(")"));

				byte[] check = digestCalculator.getDigest();

				if (!Arrays.constantTimeAreEqual(check, hashBytes))
				{
					throw new PGPException("checksum on protected data failed in SExpr");
				}
			}

			return d;
		}

		private BigInteger[] processRSASecretKey(InputStream inputStream, BigInteger n, BigInteger e, PBEProtectionRemoverFactory keyProtectionRemoverFactory)
		{
			string type;
			byte[][] basicData = extractData(inputStream, keyProtectionRemoverFactory);

			byte[] keyData = basicData[0];
			byte[] protectedAt = basicData[1];

			//
			// parse the secret key S-expr
			//
			InputStream keyIn = new ByteArrayInputStream(keyData);

			SXprUtils.skipOpenParenthesis(keyIn);
			SXprUtils.skipOpenParenthesis(keyIn);

			BigInteger d = readBigInteger("d", keyIn);
			BigInteger p = readBigInteger("p", keyIn);
			BigInteger q = readBigInteger("q", keyIn);
			BigInteger u = readBigInteger("u", keyIn);

			SXprUtils.skipCloseParenthesis(keyIn);

			SXprUtils.skipOpenParenthesis(keyIn);
			type = SXprUtils.readString(keyIn, keyIn.read());

			if (!type.Equals("hash"))
			{
				throw new PGPException("hash keyword expected");
			}
			type = SXprUtils.readString(keyIn, keyIn.read());

			if (!type.Equals("sha1"))
			{
				throw new PGPException("hash keyword expected");
			}

			byte[] hashBytes = SXprUtils.readBytes(keyIn, keyIn.read());

			SXprUtils.skipCloseParenthesis(keyIn);

			if (digestProvider != null)
			{
				PGPDigestCalculator digestCalculator = digestProvider.get(HashAlgorithmTags_Fields.SHA1);

				OutputStream dOut = digestCalculator.getOutputStream();

				dOut.write(Strings.toByteArray("(3:rsa"));

				writeCanonical(dOut, "n", n);
				writeCanonical(dOut, "e", e);
				writeCanonical(dOut, "d", d);
				writeCanonical(dOut, "p", p);
				writeCanonical(dOut, "q", q);
				writeCanonical(dOut, "u", u);

				// check protected-at
				if (protectedAt != null)
				{
					dOut.write(protectedAt);
				}

				dOut.write(Strings.toByteArray(")"));

				byte[] check = digestCalculator.getDigest();

				if (!Arrays.constantTimeAreEqual(check, hashBytes))
				{
					throw new PGPException("checksum on protected data failed in SExpr");
				}
			}

			return new BigInteger[]{d, p, q, u};
		}

		private void writeCanonical(OutputStream dOut, string label, BigInteger i)
		{
			writeCanonical(dOut, label, i.toByteArray());
		}

		private void writeCanonical(OutputStream dOut, string label, byte[] data)
		{
			dOut.write(Strings.toByteArray("(" + label.Length + ":" + label + data.Length + ":"));
			dOut.write(data);
			dOut.write(Strings.toByteArray(")"));
		}
	}

}