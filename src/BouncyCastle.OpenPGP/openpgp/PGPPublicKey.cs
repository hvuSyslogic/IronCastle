using org.bouncycastle.bcpg;

using System;

namespace org.bouncycastle.openpgp
{

	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using BCPGKey = org.bouncycastle.bcpg.BCPGKey;
	using BCPGOutputStream = org.bouncycastle.bcpg.BCPGOutputStream;
	using ContainedPacket = org.bouncycastle.bcpg.ContainedPacket;
	using DSAPublicBCPGKey = org.bouncycastle.bcpg.DSAPublicBCPGKey;
	using ECPublicBCPGKey = org.bouncycastle.bcpg.ECPublicBCPGKey;
	using ElGamalPublicBCPGKey = org.bouncycastle.bcpg.ElGamalPublicBCPGKey;
	using PublicKeyAlgorithmTags = org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
	using PublicKeyPacket = org.bouncycastle.bcpg.PublicKeyPacket;
	using RSAPublicBCPGKey = org.bouncycastle.bcpg.RSAPublicBCPGKey;
	using TrustPacket = org.bouncycastle.bcpg.TrustPacket;
	using UserAttributePacket = org.bouncycastle.bcpg.UserAttributePacket;
	using UserIDPacket = org.bouncycastle.bcpg.UserIDPacket;
	using KeyFingerPrintCalculator = org.bouncycastle.openpgp.@operator.KeyFingerPrintCalculator;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// general class to handle a PGP public key object.
	/// </summary>
	public class PGPPublicKey : PublicKeyAlgorithmTags
	{
		private static readonly int[] MASTER_KEY_CERTIFICATION_TYPES = new int[] {PGPSignature.POSITIVE_CERTIFICATION, PGPSignature.CASUAL_CERTIFICATION, PGPSignature.NO_CERTIFICATION, PGPSignature.DEFAULT_CERTIFICATION};

		internal PublicKeyPacket publicPk;
		internal TrustPacket trustPk;
		internal List keySigs = new ArrayList();
		internal List ids = new ArrayList();
		internal List idTrusts = new ArrayList();
		internal List idSigs = new ArrayList();

		internal List subSigs = null;

		private long keyID;
		private byte[] fingerprint;
		private int keyStrength;

		private void init(KeyFingerPrintCalculator fingerPrintCalculator)
		{
			BCPGKey key = publicPk.getKey();

			this.fingerprint = fingerPrintCalculator.calculateFingerprint(publicPk);

			if (publicPk.getVersion() <= 3)
			{
				RSAPublicBCPGKey rK = (RSAPublicBCPGKey)key;

				this.keyID = rK.getModulus().longValue();
				this.keyStrength = rK.getModulus().bitLength();
			}
			else
			{
				this.keyID = ((long)(fingerprint[fingerprint.Length - 8] & 0xff) << 56) | ((long)(fingerprint[fingerprint.Length - 7] & 0xff) << 48) | ((long)(fingerprint[fingerprint.Length - 6] & 0xff) << 40) | ((long)(fingerprint[fingerprint.Length - 5] & 0xff) << 32) | ((long)(fingerprint[fingerprint.Length - 4] & 0xff) << 24) | ((long)(fingerprint[fingerprint.Length - 3] & 0xff) << 16) | ((long)(fingerprint[fingerprint.Length - 2] & 0xff) << 8) | ((fingerprint[fingerprint.Length - 1] & 0xff));

				if (key is RSAPublicBCPGKey)
				{
					this.keyStrength = ((RSAPublicBCPGKey)key).getModulus().bitLength();
				}
				else if (key is DSAPublicBCPGKey)
				{
					this.keyStrength = ((DSAPublicBCPGKey)key).getP().bitLength();
				}
				else if (key is ElGamalPublicBCPGKey)
				{
					this.keyStrength = ((ElGamalPublicBCPGKey)key).getP().bitLength();
				}
				else if (key is ECPublicBCPGKey)
				{
					X9ECParameters ecParameters = ECNamedCurveTable.getByOID(((ECPublicBCPGKey)key).getCurveOID());

					if (ecParameters != null)
					{
						this.keyStrength = ecParameters.getCurve().getFieldSize();
					}
					else
					{
						this.keyStrength = -1; // unknown
					}
				}
			}
		}

		/// <summary>
		/// Create a PGP public key from a packet descriptor using the passed in fingerPrintCalculator to do calculate
		/// the fingerprint and keyID.
		/// </summary>
		/// <param name="publicKeyPacket">  packet describing the public key. </param>
		/// <param name="fingerPrintCalculator"> calculator providing the digest support ot create the key fingerprint. </param>
		/// <exception cref="PGPException">  if the packet is faulty, or the required calculations fail. </exception>
		public PGPPublicKey(PublicKeyPacket publicKeyPacket, KeyFingerPrintCalculator fingerPrintCalculator)
		{
			this.publicPk = publicKeyPacket;
			this.ids = new ArrayList();
			this.idSigs = new ArrayList();

			init(fingerPrintCalculator);
		}

		/*
		 * Constructor for a sub-key.
		 */
		public PGPPublicKey(PublicKeyPacket publicPk, TrustPacket trustPk, List sigs, KeyFingerPrintCalculator fingerPrintCalculator)
		{
			this.publicPk = publicPk;
			this.trustPk = trustPk;
			this.subSigs = sigs;

			init(fingerPrintCalculator);
		}

		public PGPPublicKey(PGPPublicKey key, TrustPacket trust, List subSigs)
		{
			this.publicPk = key.publicPk;
			this.trustPk = trust;
			this.subSigs = subSigs;

			this.fingerprint = key.fingerprint;
			this.keyID = key.keyID;
			this.keyStrength = key.keyStrength;
		}

		/// <summary>
		/// Copy constructor. </summary>
		/// <param name="pubKey"> the public key to copy. </param>
		public PGPPublicKey(PGPPublicKey pubKey)
		{
			this.publicPk = pubKey.publicPk;

			this.keySigs = new ArrayList(pubKey.keySigs);
			this.ids = new ArrayList(pubKey.ids);
			this.idTrusts = new ArrayList(pubKey.idTrusts);
			this.idSigs = new ArrayList(pubKey.idSigs.size());
			for (int i = 0; i != pubKey.idSigs.size(); i++)
			{
				this.idSigs.add(new ArrayList((ArrayList)pubKey.idSigs.get(i)));
			}

			if (pubKey.subSigs != null)
			{
				this.subSigs = new ArrayList(pubKey.subSigs.size());
				for (int i = 0; i != pubKey.subSigs.size(); i++)
				{
					this.subSigs.add(pubKey.subSigs.get(i));
				}
			}

			this.fingerprint = pubKey.fingerprint;
			this.keyID = pubKey.keyID;
			this.keyStrength = pubKey.keyStrength;
		}

		public PGPPublicKey(PublicKeyPacket publicPk, TrustPacket trustPk, List keySigs, List ids, List idTrusts, List idSigs, KeyFingerPrintCalculator fingerPrintCalculator)
		{
			this.publicPk = publicPk;
			this.trustPk = trustPk;
			this.keySigs = keySigs;
			this.ids = ids;
			this.idTrusts = idTrusts;
			this.idSigs = idSigs;

			init(fingerPrintCalculator);
		}

		/// <returns> the version of this key. </returns>
		public virtual int getVersion()
		{
			return publicPk.getVersion();
		}

		/// <returns> creation time of key. </returns>
		public virtual DateTime getCreationTime()
		{
			return publicPk.getTime();
		}

		/// <returns> number of valid days from creation time - zero means no
		/// expiry. </returns>
		/// @deprecated use getValidSeconds(): greater than version 3 keys may be valid for less than a day. 
		public virtual int getValidDays()
		{
			if (publicPk.getVersion() > 3)
			{
				long delta = this.getValidSeconds() % (24 * 60 * 60);
				int days = (int)(this.getValidSeconds() / (24 * 60 * 60));

				if (delta > 0 && days == 0)
				{
					return 1;
				}
				else
				{
					return days;
				}
			}
			else
			{
				return publicPk.getValidDays();
			}
		}

		/// <summary>
		/// Return the trust data associated with the public key, if present. </summary>
		/// <returns> a byte array with trust data, null otherwise. </returns>
		public virtual byte[] getTrustData()
		{
			if (trustPk == null)
			{
				return null;
			}

			return Arrays.clone(trustPk.getLevelAndTrustAmount());
		}

		/// <returns> number of valid seconds from creation time - zero means no
		/// expiry. </returns>
		public virtual long getValidSeconds()
		{
			if (publicPk.getVersion() > 3)
			{
				if (this.isMasterKey())
				{
					for (int i = 0; i != MASTER_KEY_CERTIFICATION_TYPES.Length; i++)
					{
						long seconds = getExpirationTimeFromSig(true, MASTER_KEY_CERTIFICATION_TYPES[i]);

						if (seconds >= 0)
						{
							return seconds;
						}
					}
				}
				else
				{
					long seconds = getExpirationTimeFromSig(false, PGPSignature.SUBKEY_BINDING);

					if (seconds >= 0)
					{
						return seconds;
					}
				}

				return 0;
			}
			else
			{
				return (long)publicPk.getValidDays() * 24 * 60 * 60;
			}
		}

		private long getExpirationTimeFromSig(bool selfSigned, int signatureType)
		{
			Iterator signatures = this.getSignaturesOfType(signatureType);
			long expiryTime = -1;
			long lastDate = -1;

			while (signatures.hasNext())
			{
				PGPSignature sig = (PGPSignature)signatures.next();

				if (!selfSigned || sig.getKeyID() == this.getKeyID())
				{
					PGPSignatureSubpacketVector hashed = sig.getHashedSubPackets();
					if (hashed == null)
					{
						continue;
					}

					long current = hashed.getKeyExpirationTime();

					if (sig.getKeyID() == this.getKeyID())
					{
						if (sig.getCreationTime().Ticks > lastDate)
						{
							lastDate = sig.getCreationTime().Ticks;
							expiryTime = current;
						}
					}
					else
					{
						if (current == 0 || current > expiryTime)
						{
							expiryTime = current;
						}
					}
				}
			}

			return expiryTime;
		}

		/// <summary>
		/// Return the keyID associated with the public key.
		/// </summary>
		/// <returns> long </returns>
		public virtual long getKeyID()
		{
			return keyID;
		}

		/// <summary>
		/// Return the fingerprint of the key.
		/// </summary>
		/// <returns> key fingerprint. </returns>
		public virtual byte[] getFingerprint()
		{
			byte[] tmp = new byte[fingerprint.Length];

			JavaSystem.arraycopy(fingerprint, 0, tmp, 0, tmp.Length);

			return tmp;
		}

		/// <summary>
		/// Return true if this key has an algorithm type that makes it suitable to use for encryption.
		/// <para>
		/// Note: with version 4 keys KeyFlags subpackets should also be considered when present for
		/// determining the preferred use of the key.
		/// 
		/// </para>
		/// </summary>
		/// <returns> true if the key algorithm is suitable for encryption. </returns>
		public virtual bool isEncryptionKey()
		{
			int algorithm = publicPk.getAlgorithm();

			return ((algorithm == PublicKeyAlgorithmTags_Fields.RSA_GENERAL) || (algorithm == PublicKeyAlgorithmTags_Fields.RSA_ENCRYPT) || (algorithm == PublicKeyAlgorithmTags_Fields.ELGAMAL_ENCRYPT) || (algorithm == PublicKeyAlgorithmTags_Fields.ELGAMAL_GENERAL) || algorithm == PublicKeyAlgorithmTags_Fields.ECDH);
		}

		/// <summary>
		/// Return true if this is a master key. </summary>
		/// <returns> true if a master key. </returns>
		public virtual bool isMasterKey()
		{
			return (subSigs == null);
		}

		/// <summary>
		/// Return the algorithm code associated with the public key.
		/// </summary>
		/// <returns> int </returns>
		public virtual int getAlgorithm()
		{
			return publicPk.getAlgorithm();
		}

		/// <summary>
		/// Return the strength of the key in bits.
		/// </summary>
		/// <returns> bit strength of key. </returns>
		public virtual int getBitStrength()
		{
			return keyStrength;
		}

		/// <summary>
		/// Return any userIDs associated with the key.
		/// </summary>
		/// <returns> an iterator of Strings. </returns>
		public virtual Iterator<string> getUserIDs()
		{
			List temp = new ArrayList();

			for (int i = 0; i != ids.size(); i++)
			{
				if (ids.get(i) is UserIDPacket)
				{
					temp.add(((UserIDPacket)ids.get(i)).getID());
				}
			}

			return temp.iterator();
		}

		/// <summary>
		/// Return any userIDs associated with the key in raw byte form. No attempt is made
		/// to convert the IDs into Strings.
		/// </summary>
		/// <returns> an iterator of Strings. </returns>
		public virtual Iterator<byte[]> getRawUserIDs()
		{
			List temp = new ArrayList();

			for (int i = 0; i != ids.size(); i++)
			{
				if (ids.get(i) is UserIDPacket)
				{
					temp.add(((UserIDPacket)ids.get(i)).getRawID());
				}
			}

			return temp.iterator();
		}

		/// <summary>
		/// Return any user attribute vectors associated with the key.
		/// </summary>
		/// <returns> an iterator of PGPUserAttributeSubpacketVector objects. </returns>
		public virtual Iterator<PGPUserAttributeSubpacketVector> getUserAttributes()
		{
			List temp = new ArrayList();

			for (int i = 0; i != ids.size(); i++)
			{
				if (ids.get(i) is PGPUserAttributeSubpacketVector)
				{
					temp.add(ids.get(i));
				}
			}

			return temp.iterator();
		}

		/// <summary>
		/// Return any signatures associated with the passed in id.
		/// </summary>
		/// <param name="id"> the id to be matched. </param>
		/// <returns> an iterator of PGPSignature objects. </returns>
		public virtual Iterator<PGPSignature> getSignaturesForID(string id)
		{
			return getSignaturesForID(new UserIDPacket(id));
		}

		/// <summary>
		/// Return any signatures associated with the passed in id.
		/// </summary>
		/// <param name="rawID"> the id to be matched in raw byte form. </param>
		/// <returns> an iterator of PGPSignature objects. </returns>
		public virtual Iterator<PGPSignature> getSignaturesForID(byte[] rawID)
		{
			return getSignaturesForID(new UserIDPacket(rawID));
		}

		/// <summary>
		/// Return any signatures associated with the passed in key identifier keyID.
		/// </summary>
		/// <param name="keyID"> the key id to be matched. </param>
		/// <returns> an iterator of PGPSignature objects issued by the key with keyID. </returns>
		public virtual Iterator<PGPSignature> getSignaturesForKeyID(long keyID)
		{
			List sigs = new ArrayList();

			for (Iterator it = getSignatures(); it.hasNext();)
			{
				PGPSignature sig = (PGPSignature)it.next();

				if (sig.getKeyID() == keyID)
				{
					sigs.add(sig);
				}
			}

			return sigs.iterator();
		}

		private Iterator getSignaturesForID(UserIDPacket id)
		{
			for (int i = 0; i != ids.size(); i++)
			{
				if (id.Equals(ids.get(i)))
				{
					return ((ArrayList)idSigs.get(i)).iterator();
				}
			}

			return null;
		}

		/// <summary>
		/// Return an iterator of signatures associated with the passed in user attributes.
		/// </summary>
		/// <param name="userAttributes"> the vector of user attributes to be matched. </param>
		/// <returns> an iterator of PGPSignature objects. </returns>
		public virtual Iterator getSignaturesForUserAttribute(PGPUserAttributeSubpacketVector userAttributes)
		{
			for (int i = 0; i != ids.size(); i++)
			{
				if (userAttributes.Equals(ids.get(i)))
				{
					return ((ArrayList)idSigs.get(i)).iterator();
				}
			}

			return null;
		}

		/// <summary>
		/// Return signatures of the passed in type that are on this key.
		/// </summary>
		/// <param name="signatureType"> the type of the signature to be returned. </param>
		/// <returns> an iterator (possibly empty) of signatures of the given type. </returns>
		public virtual Iterator getSignaturesOfType(int signatureType)
		{
			List l = new ArrayList();
			Iterator it = this.getSignatures();

			while (it.hasNext())
			{
				PGPSignature sig = (PGPSignature)it.next();

				if (sig.getSignatureType() == signatureType)
				{
					l.add(sig);
				}
			}

			return l.iterator();
		}

		/// <summary>
		/// Return all signatures/certifications associated with this key.
		/// </summary>
		/// <returns> an iterator (possibly empty) with all signatures/certifications. </returns>
		public virtual Iterator getSignatures()
		{
			if (subSigs == null)
			{
				List sigs = new ArrayList();

				sigs.addAll(keySigs);

				for (int i = 0; i != idSigs.size(); i++)
				{
					sigs.addAll((Collection)idSigs.get(i));
				}

				return sigs.iterator();
			}
			else
			{
				return subSigs.iterator();
			}
		}

		/// <summary>
		/// Return all signatures/certifications directly associated with this key (ie, not to a user id).
		/// </summary>
		/// <returns> an iterator (possibly empty) with all signatures/certifications. </returns>
		public virtual Iterator getKeySignatures()
		{
			if (subSigs == null)
			{
				List sigs = new ArrayList();
				sigs.addAll(keySigs);

				return sigs.iterator();
			}
			else
			{
				return subSigs.iterator();
			}
		}

		public virtual PublicKeyPacket getPublicKeyPacket()
		{
			return publicPk;
		}

		public virtual byte[] getEncoded()
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			this.encode(bOut, false);

			return bOut.toByteArray();
		}

		/// <summary>
		/// Return an encoding of the key, with trust packets stripped out if forTransfer is true.
		/// </summary>
		/// <param name="forTransfer"> if the purpose of encoding is to send key to other users. </param>
		/// <returns> a encoded byte array representing the key. </returns>
		/// <exception cref="IOException"> in case of encoding error. </exception>
		public virtual byte[] getEncoded(bool forTransfer)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			this.encode(bOut, forTransfer);

			return bOut.toByteArray();
		}

		public virtual void encode(OutputStream outStream)
		{
			encode(outStream, false);
		}

		/// <summary>
		/// Encode the key to outStream, with trust packets stripped out if forTransfer is true.
		/// </summary>
		/// <param name="outStream"> stream to write the key encoding to. </param>
		/// <param name="forTransfer"> if the purpose of encoding is to send key to other users. </param>
		/// <exception cref="IOException"> in case of encoding error. </exception>
		public virtual void encode(OutputStream outStream, bool forTransfer)
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

			@out.writePacket(publicPk);
			if (!forTransfer && trustPk != null)
			{
				@out.writePacket(trustPk);
			}

			if (subSigs == null) // not a sub-key
			{
				for (int i = 0; i != keySigs.size(); i++)
				{
					((PGPSignature)keySigs.get(i)).encode(@out);
				}

				for (int i = 0; i != ids.size(); i++)
				{
					if (ids.get(i) is UserIDPacket)
					{
						UserIDPacket id = (UserIDPacket)ids.get(i);

						@out.writePacket(id);
					}
					else
					{
						PGPUserAttributeSubpacketVector v = (PGPUserAttributeSubpacketVector)ids.get(i);

						@out.writePacket(new UserAttributePacket(v.toSubpacketArray()));
					}

					if (!forTransfer && idTrusts.get(i) != null)
					{
						@out.writePacket((ContainedPacket)idTrusts.get(i));
					}

					List sigs = (List)idSigs.get(i);
					for (int j = 0; j != sigs.size(); j++)
					{
						((PGPSignature)sigs.get(j)).encode(@out, forTransfer);
					}
				}
			}
			else
			{
				for (int j = 0; j != subSigs.size(); j++)
				{
					((PGPSignature)subSigs.get(j)).encode(@out, forTransfer);
				}
			}
		}

		/// <summary>
		/// Check whether this (sub)key has a revocation signature on it.
		/// </summary>
		/// <returns> boolean indicating whether this (sub)key has been revoked. </returns>
		/// @deprecated this method is poorly named, use hasRevocation(). 
		public virtual bool isRevoked()
		{
			return hasRevocation();
		}

		/// <summary>
		/// Check whether this (sub)key has a revocation signature on it.
		/// </summary>
		/// <returns> boolean indicating whether this (sub)key has had a (possibly invalid) revocation attached.. </returns>
		public virtual bool hasRevocation()
		{
			int ns = 0;
			bool revoked = false;

			if (this.isMasterKey()) // Master key
			{
				while (!revoked && (ns < keySigs.size()))
				{
					if (((PGPSignature)keySigs.get(ns++)).getSignatureType() == PGPSignature.KEY_REVOCATION)
					{
						revoked = true;
					}
				}
			}
			else // Sub-key
			{
				while (!revoked && (ns < subSigs.size()))
				{
					if (((PGPSignature)subSigs.get(ns++)).getSignatureType() == PGPSignature.SUBKEY_REVOCATION)
					{
						revoked = true;
					}
				}
			}

			return revoked;
		}

		/// <summary>
		/// Add a certification for an id to the given public key.
		/// </summary>
		/// <param name="key"> the key the certification is to be added to. </param>
		/// <param name="rawID"> the raw bytes making up the user id.. </param>
		/// <param name="certification"> the new certification. </param>
		/// <returns> the re-certified key. </returns>
		public static PGPPublicKey addCertification(PGPPublicKey key, byte[] rawID, PGPSignature certification)
		{
			return addCert(key, new UserIDPacket(rawID), certification);
		}

		/// <summary>
		/// Add a certification for an id to the given public key.
		/// </summary>
		/// <param name="key"> the key the certification is to be added to. </param>
		/// <param name="id"> the id the certification is associated with. </param>
		/// <param name="certification"> the new certification. </param>
		/// <returns> the re-certified key. </returns>
		public static PGPPublicKey addCertification(PGPPublicKey key, string id, PGPSignature certification)
		{
			return addCert(key, new UserIDPacket(id), certification);
		}

		/// <summary>
		/// Add a certification for the given UserAttributeSubpackets to the given public key.
		/// </summary>
		/// <param name="key"> the key the certification is to be added to. </param>
		/// <param name="userAttributes"> the attributes the certification is associated with. </param>
		/// <param name="certification"> the new certification. </param>
		/// <returns> the re-certified key. </returns>
		public static PGPPublicKey addCertification(PGPPublicKey key, PGPUserAttributeSubpacketVector userAttributes, PGPSignature certification)
		{
			return addCert(key, userAttributes, certification);
		}

		private static PGPPublicKey addCert(PGPPublicKey key, object id, PGPSignature certification)
		{
			PGPPublicKey returnKey = new PGPPublicKey(key);
			List sigList = null;

			for (int i = 0; i != returnKey.ids.size(); i++)
			{
				if (id.Equals(returnKey.ids.get(i)))
				{
					sigList = (List)returnKey.idSigs.get(i);
				}
			}

			if (sigList != null)
			{
				sigList.add(certification);
			}
			else
			{
				sigList = new ArrayList();

				sigList.add(certification);
				returnKey.ids.add(id);
				returnKey.idTrusts.add(null);
				returnKey.idSigs.add(sigList);
			}

			return returnKey;
		}

		/// <summary>
		/// Remove any certifications associated with a given user attribute subpacket
		///  on a key.
		/// </summary>
		/// <param name="key"> the key the certifications are to be removed from. </param>
		/// <param name="userAttributes"> the attributes to be removed. </param>
		/// <returns> the re-certified key, null if the user attribute subpacket was not found on the key. </returns>
		public static PGPPublicKey removeCertification(PGPPublicKey key, PGPUserAttributeSubpacketVector userAttributes)
		{
			return removeCert(key, userAttributes);
		}

		/// <summary>
		/// Remove any certifications associated with a given id on a key.
		/// </summary>
		/// <param name="key"> the key the certifications are to be removed from. </param>
		/// <param name="id"> the id that is to be removed. </param>
		/// <returns> the re-certified key, null if the id was not found on the key. </returns>
		public static PGPPublicKey removeCertification(PGPPublicKey key, string id)
		{
			return removeCert(key, new UserIDPacket(id));
		}

		/// <summary>
		/// Remove any certifications associated with a given id on a key.
		/// </summary>
		/// <param name="key"> the key the certifications are to be removed from. </param>
		/// <param name="rawID"> the id that is to be removed in raw byte form. </param>
		/// <returns> the re-certified key, null if the id was not found on the key. </returns>
		public static PGPPublicKey removeCertification(PGPPublicKey key, byte[] rawID)
		{
			return removeCert(key, new UserIDPacket(rawID));
		}

		private static PGPPublicKey removeCert(PGPPublicKey key, object id)
		{
			PGPPublicKey returnKey = new PGPPublicKey(key);
			bool found = false;

			for (int i = 0; i < returnKey.ids.size(); i++)
			{
				if (id.Equals(returnKey.ids.get(i)))
				{
					found = true;
					returnKey.ids.remove(i);
					returnKey.idTrusts.remove(i);
					returnKey.idSigs.remove(i);
				}
			}

			if (!found)
			{
				return null;
			}

			return returnKey;
		}

		/// <summary>
		/// Remove a certification associated with a given id on a key.
		/// </summary>
		/// <param name="key"> the key the certifications are to be removed from. </param>
		/// <param name="id"> the id that the certification is to be removed from (in its raw byte form) </param>
		/// <param name="certification"> the certification to be removed. </param>
		/// <returns> the re-certified key, null if the certification was not found. </returns>
		public static PGPPublicKey removeCertification(PGPPublicKey key, byte[] id, PGPSignature certification)
		{
			return removeCert(key, new UserIDPacket(id), certification);
		}

		/// <summary>
		/// Remove a certification associated with a given id on a key.
		/// </summary>
		/// <param name="key"> the key the certifications are to be removed from. </param>
		/// <param name="id"> the id that the certification is to be removed from. </param>
		/// <param name="certification"> the certification to be removed. </param>
		/// <returns> the re-certified key, null if the certification was not found. </returns>
		public static PGPPublicKey removeCertification(PGPPublicKey key, string id, PGPSignature certification)
		{
			return removeCert(key, new UserIDPacket(id), certification);
		}

		/// <summary>
		/// Remove a certification associated with a given user attributes on a key.
		/// </summary>
		/// <param name="key"> the key the certifications are to be removed from. </param>
		/// <param name="userAttributes"> the user attributes that the certification is to be removed from. </param>
		/// <param name="certification"> the certification to be removed. </param>
		/// <returns> the re-certified key, null if the certification was not found. </returns>
		public static PGPPublicKey removeCertification(PGPPublicKey key, PGPUserAttributeSubpacketVector userAttributes, PGPSignature certification)
		{
			return removeCert(key, userAttributes, certification);
		}

		private static PGPPublicKey removeCert(PGPPublicKey key, object id, PGPSignature certification)
		{
			PGPPublicKey returnKey = new PGPPublicKey(key);
			bool found = false;

			for (int i = 0; i < returnKey.ids.size(); i++)
			{
				if (id.Equals(returnKey.ids.get(i)))
				{
					found = ((List)returnKey.idSigs.get(i)).remove(certification);
				}
			}

			if (!found)
			{
				return null;
			}

			return returnKey;
		}

		/// <summary>
		/// Add a revocation or some other key certification to a key.
		/// </summary>
		/// <param name="key"> the key the revocation is to be added to. </param>
		/// <param name="certification"> the key signature to be added. </param>
		/// <returns> the new changed public key object. </returns>
		public static PGPPublicKey addCertification(PGPPublicKey key, PGPSignature certification)
		{
			if (key.isMasterKey())
			{
				if (certification.getSignatureType() == PGPSignature.SUBKEY_REVOCATION)
				{
					throw new IllegalArgumentException("signature type incorrect for master key revocation.");
				}
			}
			else
			{
				if (certification.getSignatureType() == PGPSignature.KEY_REVOCATION)
				{
					throw new IllegalArgumentException("signature type incorrect for sub-key revocation.");
				}
			}

			PGPPublicKey returnKey = new PGPPublicKey(key);

			if (returnKey.subSigs != null)
			{
				returnKey.subSigs.add(certification);
			}
			else
			{
				returnKey.keySigs.add(certification);
			}

			return returnKey;
		}

		/// <summary>
		/// Remove a certification from the key.
		/// </summary>
		/// <param name="key"> the key the certifications are to be removed from. </param>
		/// <param name="certification"> the certification to be removed. </param>
		/// <returns> the modified key, null if the certification was not found. </returns>
		public static PGPPublicKey removeCertification(PGPPublicKey key, PGPSignature certification)
		{
			PGPPublicKey returnKey = new PGPPublicKey(key);
			bool found;

			if (returnKey.subSigs != null)
			{
				found = returnKey.subSigs.remove(certification);
			}
			else
			{
				found = returnKey.keySigs.remove(certification);
			}

			if (!found)
			{
				for (Iterator it = key.getRawUserIDs(); it.hasNext();)
				{
					byte[] rawID = (byte[])it.next();
					for (Iterator sIt = key.getSignaturesForID(rawID); sIt.hasNext();)
					{
						if (certification == sIt.next())
						{
							found = true;
							returnKey = PGPPublicKey.removeCertification(returnKey, rawID, certification);
						}
					}
				}

				if (!found)
				{
					for (Iterator it = key.getUserAttributes(); it.hasNext();)
					{
						PGPUserAttributeSubpacketVector id = (PGPUserAttributeSubpacketVector)it.next();
						for (Iterator sIt = key.getSignaturesForUserAttribute(id); sIt.hasNext();)
						{
							if (certification == sIt.next())
							{
								found = true;
								returnKey = PGPPublicKey.removeCertification(returnKey, id, certification);
							}
						}
					}
				}
			}

			return returnKey;
		}
	}

}