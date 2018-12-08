using org.bouncycastle.bcpg;

using System;

namespace org.bouncycastle.openpgp
{

	using BCPGInputStream = org.bouncycastle.bcpg.BCPGInputStream;
	using BCPGObject = org.bouncycastle.bcpg.BCPGObject;
	using BCPGOutputStream = org.bouncycastle.bcpg.BCPGOutputStream;
	using ContainedPacket = org.bouncycastle.bcpg.ContainedPacket;
	using DSASecretBCPGKey = org.bouncycastle.bcpg.DSASecretBCPGKey;
	using ECSecretBCPGKey = org.bouncycastle.bcpg.ECSecretBCPGKey;
	using ElGamalSecretBCPGKey = org.bouncycastle.bcpg.ElGamalSecretBCPGKey;
	using HashAlgorithmTags = org.bouncycastle.bcpg.HashAlgorithmTags;
	using PublicKeyPacket = org.bouncycastle.bcpg.PublicKeyPacket;
	using RSASecretBCPGKey = org.bouncycastle.bcpg.RSASecretBCPGKey;
	using S2K = org.bouncycastle.bcpg.S2K;
	using SecretKeyPacket = org.bouncycastle.bcpg.SecretKeyPacket;
	using SecretSubkeyPacket = org.bouncycastle.bcpg.SecretSubkeyPacket;
	using SymmetricKeyAlgorithmTags = org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
	using UserAttributePacket = org.bouncycastle.bcpg.UserAttributePacket;
	using UserIDPacket = org.bouncycastle.bcpg.UserIDPacket;
	using SExprParser = org.bouncycastle.gpg.SExprParser;
	using KeyFingerPrintCalculator = org.bouncycastle.openpgp.@operator.KeyFingerPrintCalculator;
	using PBEProtectionRemoverFactory = org.bouncycastle.openpgp.@operator.PBEProtectionRemoverFactory;
	using PBESecretKeyDecryptor = org.bouncycastle.openpgp.@operator.PBESecretKeyDecryptor;
	using PBESecretKeyEncryptor = org.bouncycastle.openpgp.@operator.PBESecretKeyEncryptor;
	using PGPContentSignerBuilder = org.bouncycastle.openpgp.@operator.PGPContentSignerBuilder;
	using PGPDigestCalculator = org.bouncycastle.openpgp.@operator.PGPDigestCalculator;

	/// <summary>
	/// general class to handle and construct  a PGP secret key object.
	/// </summary>
	public class PGPSecretKey
	{
		internal SecretKeyPacket secret;
		internal PGPPublicKey pub;

		public PGPSecretKey(SecretKeyPacket secret, PGPPublicKey pub)
		{
			this.secret = secret;
			this.pub = pub;
		}

		public PGPSecretKey(PGPPrivateKey privKey, PGPPublicKey pubKey, PGPDigestCalculator checksumCalculator, PBESecretKeyEncryptor keyEncryptor) : this(privKey, pubKey, checksumCalculator, false, keyEncryptor)
		{
		}

		/// <summary>
		/// Construct a PGPSecretKey using the passed in private key and public key. This constructor will not add any
		/// certifications but assumes that pubKey already has what is required.
		/// </summary>
		/// <param name="privKey">            the private key component. </param>
		/// <param name="pubKey">             the public key component. </param>
		/// <param name="checksumCalculator"> a calculator for the private key checksum </param>
		/// <param name="isMasterKey">        true if the key is a master key, false otherwise. </param>
		/// <param name="keyEncryptor">       an encryptor for the key if required (null otherwise). </param>
		/// <exception cref="PGPException"> if there is an issue creating the secret key packet. </exception>
		public PGPSecretKey(PGPPrivateKey privKey, PGPPublicKey pubKey, PGPDigestCalculator checksumCalculator, bool isMasterKey, PBESecretKeyEncryptor keyEncryptor)
		{
			this.pub = pubKey;
			this.secret = buildSecretKeyPacket(isMasterKey, privKey, pubKey, keyEncryptor, checksumCalculator);
		}

		private static SecretKeyPacket buildSecretKeyPacket(bool isMasterKey, PGPPrivateKey privKey, PGPPublicKey pubKey, PBESecretKeyEncryptor keyEncryptor, PGPDigestCalculator checksumCalculator)
		{
			BCPGObject secKey = (BCPGObject)privKey.getPrivateKeyDataPacket();

			if (secKey == null)
			{
				if (isMasterKey)
				{
					return new SecretKeyPacket(pubKey.publicPk, SymmetricKeyAlgorithmTags_Fields.NULL, null, null, new byte[0]);
				}
				else
				{
					return new SecretSubkeyPacket(pubKey.publicPk, SymmetricKeyAlgorithmTags_Fields.NULL, null, null, new byte[0]);
				}
			}

			try
			{
				ByteArrayOutputStream bOut = new ByteArrayOutputStream();
				BCPGOutputStream pOut = new BCPGOutputStream(bOut);

				pOut.writeObject(secKey);

				byte[] keyData = bOut.toByteArray();

				int encAlgorithm = (keyEncryptor != null) ? keyEncryptor.getAlgorithm() : SymmetricKeyAlgorithmTags_Fields.NULL;

				if (encAlgorithm != SymmetricKeyAlgorithmTags_Fields.NULL)
				{
					pOut.write(checksum(checksumCalculator, keyData, keyData.Length));

					keyData = bOut.toByteArray(); // include checksum

					byte[] encData = keyEncryptor.encryptKeyData(keyData, 0, keyData.Length);
					byte[] iv = keyEncryptor.getCipherIV();

					S2K s2k = keyEncryptor.getS2K();

					int s2kUsage;

					if (checksumCalculator != null)
					{
						if (checksumCalculator.getAlgorithm() != HashAlgorithmTags_Fields.SHA1)
						{
							throw new PGPException("only SHA1 supported for key checksum calculations.");
						}
						s2kUsage = SecretKeyPacket.USAGE_SHA1;
					}
					else
					{
						s2kUsage = SecretKeyPacket.USAGE_CHECKSUM;
					}

					if (isMasterKey)
					{
						return new SecretKeyPacket(pubKey.publicPk, encAlgorithm, s2kUsage, s2k, iv, encData);
					}
					else
					{
						return new SecretSubkeyPacket(pubKey.publicPk, encAlgorithm, s2kUsage, s2k, iv, encData);
					}
				}
				else
				{
					pOut.write(checksum(null, keyData, keyData.Length));

					if (isMasterKey)
					{
						return new SecretKeyPacket(pubKey.publicPk, encAlgorithm, null, null, bOut.toByteArray());
					}
					else
					{
						return new SecretSubkeyPacket(pubKey.publicPk, encAlgorithm, null, null, bOut.toByteArray());
					}
				}
			}
			catch (PGPException e)
			{
				throw e;
			}
			catch (Exception e)
			{
				throw new PGPException("Exception encrypting key", e);
			}
		}

		/// <summary>
		/// Construct a PGPSecretKey using the passed in private/public key pair and binding it to the passed in id
		/// using a generated certification of certificationLevel.The secret key checksum is calculated using the original
		/// non-digest based checksum.
		/// </summary>
		/// <param name="certificationLevel">         the type of certification to be added. </param>
		/// <param name="keyPair">                    the public/private keys to use. </param>
		/// <param name="id">                         the id to bind to the key. </param>
		/// <param name="hashedPcks">                 the hashed packets to be added to the certification. </param>
		/// <param name="unhashedPcks">               the unhashed packets to be added to the certification. </param>
		/// <param name="certificationSignerBuilder"> the builder for generating the certification. </param>
		/// <param name="keyEncryptor">               an encryptor for the key if required (null otherwise). </param>
		/// <exception cref="PGPException"> if there is an issue creating the secret key packet or the certification. </exception>
		public PGPSecretKey(int certificationLevel, PGPKeyPair keyPair, string id, PGPSignatureSubpacketVector hashedPcks, PGPSignatureSubpacketVector unhashedPcks, PGPContentSignerBuilder certificationSignerBuilder, PBESecretKeyEncryptor keyEncryptor) : this(certificationLevel, keyPair, id, null, hashedPcks, unhashedPcks, certificationSignerBuilder, keyEncryptor)
		{
		}

		/// <summary>
		/// Construct a PGPSecretKey using the passed in private/public key pair and binding it to the passed in id
		/// using a generated certification of certificationLevel.
		/// </summary>
		/// <param name="certificationLevel">         the type of certification to be added. </param>
		/// <param name="keyPair">                    the public/private keys to use. </param>
		/// <param name="id">                         the id to bind to the key. </param>
		/// <param name="checksumCalculator">         a calculator for the private key checksum. </param>
		/// <param name="hashedPcks">                 the hashed packets to be added to the certification. </param>
		/// <param name="unhashedPcks">               the unhashed packets to be added to the certification. </param>
		/// <param name="certificationSignerBuilder"> the builder for generating the certification. </param>
		/// <param name="keyEncryptor">               an encryptor for the key if required (null otherwise). </param>
		/// <exception cref="PGPException"> if there is an issue creating the secret key packet or the certification. </exception>
		public PGPSecretKey(int certificationLevel, PGPKeyPair keyPair, string id, PGPDigestCalculator checksumCalculator, PGPSignatureSubpacketVector hashedPcks, PGPSignatureSubpacketVector unhashedPcks, PGPContentSignerBuilder certificationSignerBuilder, PBESecretKeyEncryptor keyEncryptor) : this(keyPair.getPrivateKey(), certifiedPublicKey(certificationLevel, keyPair, id, hashedPcks, unhashedPcks, certificationSignerBuilder), checksumCalculator, true, keyEncryptor)
		{
		}

		private static PGPPublicKey certifiedPublicKey(int certificationLevel, PGPKeyPair keyPair, string id, PGPSignatureSubpacketVector hashedPcks, PGPSignatureSubpacketVector unhashedPcks, PGPContentSignerBuilder certificationSignerBuilder)
		{
			PGPSignatureGenerator sGen;

			try
			{
				sGen = new PGPSignatureGenerator(certificationSignerBuilder);
			}
			catch (Exception e)
			{
				throw new PGPException("creating signature generator: " + e, e);
			}

			//
			// generate the certification
			//
			sGen.init(certificationLevel, keyPair.getPrivateKey());

			sGen.setHashedSubpackets(hashedPcks);
			sGen.setUnhashedSubpackets(unhashedPcks);

			try
			{
				PGPSignature certification = sGen.generateCertification(id, keyPair.getPublicKey());

				return PGPPublicKey.addCertification(keyPair.getPublicKey(), id, certification);
			}
			catch (Exception e)
			{
				throw new PGPException("exception doing certification: " + e, e);
			}
		}

		/// <summary>
		/// Return true if this key has an algorithm type that makes it suitable to use for signing.
		/// <para>
		/// Note: with version 4 keys KeyFlags subpackets should also be considered when present for
		/// determining the preferred use of the key.
		/// 
		/// </para>
		/// </summary>
		/// <returns> true if this key algorithm is suitable for use with signing. </returns>
		public virtual bool isSigningKey()
		{
			int algorithm = pub.getAlgorithm();

			return ((algorithm == PGPPublicKey.RSA_GENERAL) || (algorithm == PGPPublicKey.RSA_SIGN) || (algorithm == PGPPublicKey.DSA) || (algorithm == PGPPublicKey.ECDSA) || (algorithm == PGPPublicKey.ELGAMAL_GENERAL));
		}

		/// <summary>
		/// Return true if this is a master key.
		/// </summary>
		/// <returns> true if a master key. </returns>
		public virtual bool isMasterKey()
		{
			return pub.isMasterKey();
		}

		/// <summary>
		/// Detect if the Secret Key's Private Key is empty or not
		/// </summary>
		/// <returns> boolean whether or not the private key is empty </returns>
		public virtual bool isPrivateKeyEmpty()
		{
			byte[] secKeyData = secret.getSecretKeyData();

			return (secKeyData == null || secKeyData.Length < 1);
		}

		/// <summary>
		/// return the algorithm the key is encrypted with.
		/// </summary>
		/// <returns> the algorithm used to encrypt the secret key. </returns>
		public virtual int getKeyEncryptionAlgorithm()
		{
			return secret.getEncAlgorithm();
		}

		/// <summary>
		/// Return the keyID of the public key associated with this key.
		/// </summary>
		/// <returns> the keyID associated with this key. </returns>
		public virtual long getKeyID()
		{
			return pub.getKeyID();
		}

		/// <summary>
		/// Return the S2K usage associated with this key.
		/// </summary>
		/// <returns> the key's S2K usage </returns>
		public virtual int getS2KUsage()
		{
			return secret.getS2KUsage();
		}

		/// <summary>
		/// Return the S2K used to process this key
		/// </summary>
		/// <returns> the key's S2K, null if one is not present. </returns>
		public virtual S2K getS2K()
		{
			return secret.getS2K();
		}

		/// <summary>
		/// Return the public key associated with this key.
		/// </summary>
		/// <returns> the public key for this key. </returns>
		public virtual PGPPublicKey getPublicKey()
		{
			return pub;
		}

		/// <summary>
		/// Return any userIDs associated with the key.
		/// </summary>
		/// <returns> an iterator of Strings. </returns>
		public virtual Iterator<string> getUserIDs()
		{
			return pub.getUserIDs();
		}

		/// <summary>
		/// Return any user attribute vectors associated with the key.
		/// </summary>
		/// <returns> an iterator of PGPUserAttributeSubpacketVector. </returns>
		public virtual Iterator<PGPUserAttributeSubpacketVector> getUserAttributes()
		{
			return pub.getUserAttributes();
		}

		private byte[] extractKeyData(PBESecretKeyDecryptor decryptorFactory)
		{
			byte[] encData = secret.getSecretKeyData();
			byte[] data = null;

			if (secret.getEncAlgorithm() != SymmetricKeyAlgorithmTags_Fields.NULL)
			{
				try
				{
					if (secret.getPublicKeyPacket().getVersion() == 4)
					{
						byte[] key = decryptorFactory.makeKeyFromPassPhrase(secret.getEncAlgorithm(), secret.getS2K());

						data = decryptorFactory.recoverKeyData(secret.getEncAlgorithm(), key, secret.getIV(), encData, 0, encData.Length);

						bool useSHA1 = secret.getS2KUsage() == SecretKeyPacket.USAGE_SHA1;
						byte[] check = checksum(useSHA1 ? decryptorFactory.getChecksumCalculator(HashAlgorithmTags_Fields.SHA1) : null, data, (useSHA1) ? data.Length - 20 : data.Length - 2);

						for (int i = 0; i != check.Length; i++)
						{
							if (check[i] != data[data.Length - check.Length + i])
							{
								throw new PGPException("checksum mismatch at " + i + " of " + check.Length);
							}
						}
					}
					else // version 2 or 3, RSA only.
					{
						byte[] key = decryptorFactory.makeKeyFromPassPhrase(secret.getEncAlgorithm(), secret.getS2K());

						data = new byte[encData.Length];

						byte[] iv = new byte[secret.getIV().Length];

						JavaSystem.arraycopy(secret.getIV(), 0, iv, 0, iv.Length);

						//
						// read in the four numbers
						//
						int pos = 0;

						for (int i = 0; i != 4; i++)
						{
							int encLen = (((encData[pos] << 8) | (encData[pos + 1] & 0xff)) + 7) / 8;

							data[pos] = encData[pos];
							data[pos + 1] = encData[pos + 1];

							byte[] tmp = decryptorFactory.recoverKeyData(secret.getEncAlgorithm(), key, iv, encData, pos + 2, encLen);
							JavaSystem.arraycopy(tmp, 0, data, pos + 2, tmp.Length);
							pos += 2 + encLen;

							if (i != 3)
							{
								JavaSystem.arraycopy(encData, pos - iv.Length, iv, 0, iv.Length);
							}
						}

						//
						// verify and copy checksum
						//

						data[pos] = encData[pos];
						data[pos + 1] = encData[pos + 1];

						int cs = ((encData[pos] << 8) & 0xff00) | (encData[pos + 1] & 0xff);
						int calcCs = 0;
						for (int j = 0; j < data.Length - 2; j++)
						{
							calcCs += data[j] & 0xff;
						}

						calcCs &= 0xffff;
						if (calcCs != cs)
						{
							throw new PGPException("checksum mismatch: passphrase wrong, expected " + cs.ToString("x") + " found " + calcCs.ToString("x"));
						}
					}
				}
				catch (PGPException e)
				{
					throw e;
				}
				catch (Exception e)
				{
					throw new PGPException("Exception decrypting key", e);
				}
			}
			else
			{
				data = encData;
			}

			return data;
		}

		/// <summary>
		/// Extract a PGPPrivate key from the SecretKey's encrypted contents.
		/// </summary>
		/// <param name="decryptorFactory"> factory to use to generate a decryptor for the passed in secretKey. </param>
		/// <returns> PGPPrivateKey  the unencrypted private key. </returns>
		/// <exception cref="PGPException"> on failure. </exception>
		public virtual PGPPrivateKey extractPrivateKey(PBESecretKeyDecryptor decryptorFactory)
		{
			if (isPrivateKeyEmpty())
			{
				return null;
			}

			PublicKeyPacket pubPk = secret.getPublicKeyPacket();

			try
			{
				byte[] data = extractKeyData(decryptorFactory);
				BCPGInputStream @in = new BCPGInputStream(new ByteArrayInputStream(data));


				switch (pubPk.getAlgorithm())
				{
				case PGPPublicKey.RSA_ENCRYPT:
				case PGPPublicKey.RSA_GENERAL:
				case PGPPublicKey.RSA_SIGN:
					RSASecretBCPGKey rsaPriv = new RSASecretBCPGKey(@in);

					return new PGPPrivateKey(this.getKeyID(), pubPk, rsaPriv);
				case PGPPublicKey.DSA:
					DSASecretBCPGKey dsaPriv = new DSASecretBCPGKey(@in);

					return new PGPPrivateKey(this.getKeyID(), pubPk, dsaPriv);
				case PGPPublicKey.ELGAMAL_ENCRYPT:
				case PGPPublicKey.ELGAMAL_GENERAL:
					ElGamalSecretBCPGKey elPriv = new ElGamalSecretBCPGKey(@in);

					return new PGPPrivateKey(this.getKeyID(), pubPk, elPriv);
				case PGPPublicKey.ECDH:
				case PGPPublicKey.ECDSA:
					ECSecretBCPGKey ecPriv = new ECSecretBCPGKey(@in);

					return new PGPPrivateKey(this.getKeyID(), pubPk, ecPriv);
				default:
					throw new PGPException("unknown public key algorithm encountered");
				}
			}
			catch (PGPException e)
			{
				throw e;
			}
			catch (Exception e)
			{
				throw new PGPException("Exception constructing key", e);
			}
		}

		private static byte[] checksum(PGPDigestCalculator digCalc, byte[] bytes, int length)
		{
			if (digCalc != null)
			{
				OutputStream dOut = digCalc.getOutputStream();

				try
				{
					dOut.write(bytes, 0, length);

					dOut.close();
				}
				catch (Exception e)
				{
					throw new PGPException("checksum digest calculation failed: " + e.Message, e);
				}
				return digCalc.getDigest();
			}
			else
			{
				int checksum = 0;

				for (int i = 0; i != length; i++)
				{
					checksum += bytes[i] & 0xff;
				}

				byte[] check = new byte[2];

				check[0] = (byte)(checksum >> 8);
				check[1] = (byte)checksum;

				return check;
			}
		}

		public virtual byte[] getEncoded()
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			this.encode(bOut);

			return bOut.toByteArray();
		}

		public virtual void encode(OutputStream outStream)
		{
			BCPGOutputStream @out;

			if (outStream is BCPGOutputStream)
			{
				@out = (BCPGOutputStream)outStream;
			}
			else
			{
				@out = new BCPGOutputStream(outStream);
			}

			@out.writePacket(secret);
			if (pub.trustPk != null)
			{
				@out.writePacket(pub.trustPk);
			}

			if (pub.subSigs == null) // is not a sub key
			{
				for (int i = 0; i != pub.keySigs.size(); i++)
				{
					((PGPSignature)pub.keySigs.get(i)).encode(@out);
				}

				for (int i = 0; i != pub.ids.size(); i++)
				{
					if (pub.ids.get(i) is UserIDPacket)
					{
						UserIDPacket id = (UserIDPacket)pub.ids.get(i);

						@out.writePacket(id);
					}
					else
					{
						PGPUserAttributeSubpacketVector v = (PGPUserAttributeSubpacketVector)pub.ids.get(i);

						@out.writePacket(new UserAttributePacket(v.toSubpacketArray()));
					}

					if (pub.idTrusts.get(i) != null)
					{
						@out.writePacket((ContainedPacket)pub.idTrusts.get(i));
					}

					List sigs = (ArrayList)pub.idSigs.get(i);

					for (int j = 0; j != sigs.size(); j++)
					{
						((PGPSignature)sigs.get(j)).encode(@out);
					}
				}
			}
			else
			{
				for (int j = 0; j != pub.subSigs.size(); j++)
				{
					((PGPSignature)pub.subSigs.get(j)).encode(@out);
				}
			}
		}

		/// <summary>
		/// Return a copy of the passed in secret key, encrypted using a new
		/// password and the passed in algorithm.
		/// </summary>
		/// <param name="key">             the PGPSecretKey to be copied. </param>
		/// <param name="oldKeyDecryptor"> the current decryptor based on the current password for key. </param>
		/// <param name="newKeyEncryptor"> a new encryptor based on a new password for encrypting the secret key material. </param>
		public static PGPSecretKey copyWithNewPassword(PGPSecretKey key, PBESecretKeyDecryptor oldKeyDecryptor, PBESecretKeyEncryptor newKeyEncryptor)
		{
			if (key.isPrivateKeyEmpty())
			{
				throw new PGPException("no private key in this SecretKey - public key present only.");
			}

			byte[] rawKeyData = key.extractKeyData(oldKeyDecryptor);
			int s2kUsage = key.secret.getS2KUsage();
			byte[] iv = null;
			S2K s2k = null;
			byte[] keyData;
			int newEncAlgorithm = SymmetricKeyAlgorithmTags_Fields.NULL;

			if (newKeyEncryptor == null || newKeyEncryptor.getAlgorithm() == SymmetricKeyAlgorithmTags_Fields.NULL)
			{
				s2kUsage = SecretKeyPacket.USAGE_NONE;
				if (key.secret.getS2KUsage() == SecretKeyPacket.USAGE_SHA1) // SHA-1 hash, need to rewrite checksum
				{
					keyData = new byte[rawKeyData.Length - 18];

					JavaSystem.arraycopy(rawKeyData, 0, keyData, 0, keyData.Length - 2);

					byte[] check = checksum(null, keyData, keyData.Length - 2);

					keyData[keyData.Length - 2] = check[0];
					keyData[keyData.Length - 1] = check[1];
				}
				else
				{
					keyData = rawKeyData;
				}
			}
			else
			{
				if (s2kUsage == SecretKeyPacket.USAGE_NONE)
				{
					s2kUsage = SecretKeyPacket.USAGE_CHECKSUM;
				}
				if (key.secret.getPublicKeyPacket().getVersion() < 4)
				{
					// Version 2 or 3 - RSA Keys only

					byte[] encKey = newKeyEncryptor.getKey();
					keyData = new byte[rawKeyData.Length];

					if (newKeyEncryptor.getHashAlgorithm() != HashAlgorithmTags_Fields.MD5)
					{
						throw new PGPException("MD5 Digest Calculator required for version 3 key encryptor.");
					}

					//
					// process 4 numbers
					//
					int pos = 0;
					for (int i = 0; i != 4; i++)
					{
						int encLen = (((rawKeyData[pos] << 8) | (rawKeyData[pos + 1] & 0xff)) + 7) / 8;

						keyData[pos] = rawKeyData[pos];
						keyData[pos + 1] = rawKeyData[pos + 1];

						byte[] tmp;
						if (i == 0)
						{
							tmp = newKeyEncryptor.encryptKeyData(encKey, rawKeyData, pos + 2, encLen);
							iv = newKeyEncryptor.getCipherIV();

						}
						else
						{
							byte[] tmpIv = new byte[iv.Length];

							JavaSystem.arraycopy(keyData, pos - iv.Length, tmpIv, 0, tmpIv.Length);
							tmp = newKeyEncryptor.encryptKeyData(encKey, tmpIv, rawKeyData, pos + 2, encLen);
						}

						JavaSystem.arraycopy(tmp, 0, keyData, pos + 2, tmp.Length);
						pos += 2 + encLen;
					}

					//
					// copy in checksum.
					//
					keyData[pos] = rawKeyData[pos];
					keyData[pos + 1] = rawKeyData[pos + 1];

					s2k = newKeyEncryptor.getS2K();
					newEncAlgorithm = newKeyEncryptor.getAlgorithm();
				}
				else
				{
					keyData = newKeyEncryptor.encryptKeyData(rawKeyData, 0, rawKeyData.Length);

					iv = newKeyEncryptor.getCipherIV();

					s2k = newKeyEncryptor.getS2K();

					newEncAlgorithm = newKeyEncryptor.getAlgorithm();
				}
			}

			SecretKeyPacket secret;
			if (key.secret is SecretSubkeyPacket)
			{
				secret = new SecretSubkeyPacket(key.secret.getPublicKeyPacket(), newEncAlgorithm, s2kUsage, s2k, iv, keyData);
			}
			else
			{
				secret = new SecretKeyPacket(key.secret.getPublicKeyPacket(), newEncAlgorithm, s2kUsage, s2k, iv, keyData);
			}

			return new PGPSecretKey(secret, key.pub);
		}

		/// <summary>
		/// Replace the passed the public key on the passed in secret key.
		/// </summary>
		/// <param name="secretKey"> secret key to change </param>
		/// <param name="publicKey"> new public key. </param>
		/// <returns> a new secret key. </returns>
		/// <exception cref="IllegalArgumentException"> if keyIDs do not match. </exception>
		public static PGPSecretKey replacePublicKey(PGPSecretKey secretKey, PGPPublicKey publicKey)
		{
			if (publicKey.getKeyID() != secretKey.getKeyID())
			{
				throw new IllegalArgumentException("keyIDs do not match");
			}

			return new PGPSecretKey(secretKey.secret, publicKey);
		}

		/// <summary>
		/// Parse a secret key from one of the GPG S expression keys associating it with the passed in public key.
		/// </summary>
		/// <returns> a secret key object. </returns>
		/// @deprecated use org.bouncycastle.gpg.SExprParser - it will also allow you to verify the protection checksum if it is available. 
		public static PGPSecretKey parseSecretKeyFromSExpr(InputStream inputStream, PBEProtectionRemoverFactory keyProtectionRemoverFactory, PGPPublicKey pubKey)
		{
			return (new SExprParser(null)).parseSecretKey(inputStream, keyProtectionRemoverFactory, pubKey);
		}

		/// <summary>
		/// Parse a secret key from one of the GPG S expression keys.
		/// </summary>
		/// <returns> a secret key object. </returns>
		/// @deprecated use org.bouncycastle.gpg.SExprParser - it will also allow you to verify the protection checksum if it is available. 
		public static PGPSecretKey parseSecretKeyFromSExpr(InputStream inputStream, PBEProtectionRemoverFactory keyProtectionRemoverFactory, KeyFingerPrintCalculator fingerPrintCalculator)
		{
			return (new SExprParser(null)).parseSecretKey(inputStream, keyProtectionRemoverFactory, fingerPrintCalculator);
		}
	}

}