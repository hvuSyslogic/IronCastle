using org.bouncycastle.bcpg;

namespace org.bouncycastle.openpgp
{

	using BCPGInputStream = org.bouncycastle.bcpg.BCPGInputStream;
	using PacketTags = org.bouncycastle.bcpg.PacketTags;
	using PublicSubkeyPacket = org.bouncycastle.bcpg.PublicSubkeyPacket;
	using SecretKeyPacket = org.bouncycastle.bcpg.SecretKeyPacket;
	using SecretSubkeyPacket = org.bouncycastle.bcpg.SecretSubkeyPacket;
	using TrustPacket = org.bouncycastle.bcpg.TrustPacket;
	using KeyFingerPrintCalculator = org.bouncycastle.openpgp.@operator.KeyFingerPrintCalculator;
	using PBESecretKeyDecryptor = org.bouncycastle.openpgp.@operator.PBESecretKeyDecryptor;
	using PBESecretKeyEncryptor = org.bouncycastle.openpgp.@operator.PBESecretKeyEncryptor;
	using Arrays = org.bouncycastle.util.Arrays;
	using Iterable = org.bouncycastle.util.Iterable;

	/// <summary>
	/// Class to hold a single master secret key and its subkeys.
	/// <para>
	/// Often PGP keyring files consist of multiple master keys, if you are trying to process
	/// or construct one of these you should use the <seealso cref="PGPSecretKeyRingCollection"/> class.
	/// </para>
	/// </summary>
	public class PGPSecretKeyRing : PGPKeyRing, Iterable<PGPSecretKey>
	{
		internal List keys;
		internal List extraPubKeys;

		private static List checkKeys(List keys)
		{
			List rv = new ArrayList(keys.size());

			for (int i = 0; i != keys.size(); i++)
			{
				PGPSecretKey k = (PGPSecretKey)keys.get(i);

				if (i == 0)
				{
					if (!k.isMasterKey())
					{
						throw new IllegalArgumentException("key 0 must be a master key");
					}
				}
				else
				{
					if (k.isMasterKey())
					{
						throw new IllegalArgumentException("key 0 can be only master key");
					}
				}
				rv.add(k);
			}

			return rv;
		}

		/// <summary>
		/// Base constructor from a list of keys representing a secret key ring (a master key and its
		/// associated sub-keys).
		/// </summary>
		/// <param name="secKeys"> the list of keys making up the ring. </param>
		public PGPSecretKeyRing(List secKeys) : this(checkKeys(secKeys), new ArrayList())
		{
		}

		private PGPSecretKeyRing(List keys, List extraPubKeys)
		{
			this.keys = keys;
			this.extraPubKeys = extraPubKeys;
		}

		public PGPSecretKeyRing(byte[] encoding, KeyFingerPrintCalculator fingerPrintCalculator) : this(new ByteArrayInputStream(encoding), fingerPrintCalculator)
		{
		}

		public PGPSecretKeyRing(InputStream @in, KeyFingerPrintCalculator fingerPrintCalculator)
		{
			this.keys = new ArrayList();
			this.extraPubKeys = new ArrayList();

			BCPGInputStream pIn = wrap(@in);

			int initialTag = pIn.nextPacketTag();
			if (initialTag != PacketTags_Fields.SECRET_KEY && initialTag != PacketTags_Fields.SECRET_SUBKEY)
			{
				throw new IOException("secret key ring doesn't start with secret key tag: " + "tag 0x" + initialTag.ToString("x"));
			}

			SecretKeyPacket secret = (SecretKeyPacket)pIn.readPacket();

			//
			// ignore GPG comment packets if found.
			//
			while (pIn.nextPacketTag() == PacketTags_Fields.EXPERIMENTAL_2)
			{
				pIn.readPacket();
			}

			TrustPacket trust = readOptionalTrustPacket(pIn);

			// revocation and direct signatures
			List keySigs = readSignaturesAndTrust(pIn);

			List ids = new ArrayList();
			List idTrusts = new ArrayList();
			List idSigs = new ArrayList();
			readUserIDs(pIn, ids, idTrusts, idSigs);

			keys.add(new PGPSecretKey(secret, new PGPPublicKey(secret.getPublicKeyPacket(), trust, keySigs, ids, idTrusts, idSigs, fingerPrintCalculator)));


			// Read subkeys
			while (pIn.nextPacketTag() == PacketTags_Fields.SECRET_SUBKEY || pIn.nextPacketTag() == PacketTags_Fields.PUBLIC_SUBKEY)
			{
				if (pIn.nextPacketTag() == PacketTags_Fields.SECRET_SUBKEY)
				{
					SecretSubkeyPacket sub = (SecretSubkeyPacket)pIn.readPacket();

					//
					// ignore GPG comment packets if found.
					//
					while (pIn.nextPacketTag() == PacketTags_Fields.EXPERIMENTAL_2)
					{
						pIn.readPacket();
					}

					TrustPacket subTrust = readOptionalTrustPacket(pIn);
					List sigList = readSignaturesAndTrust(pIn);

					keys.add(new PGPSecretKey(sub, new PGPPublicKey(sub.getPublicKeyPacket(), subTrust, sigList, fingerPrintCalculator)));
				}
				else
				{
					PublicSubkeyPacket sub = (PublicSubkeyPacket)pIn.readPacket();

					TrustPacket subTrust = readOptionalTrustPacket(pIn);
					List sigList = readSignaturesAndTrust(pIn);

					extraPubKeys.add(new PGPPublicKey(sub, subTrust, sigList, fingerPrintCalculator));
				}
			}
		}

		/// <summary>
		/// Return the public key for the master key.
		/// </summary>
		/// <returns> PGPPublicKey </returns>
		public override PGPPublicKey getPublicKey()
		{
			return ((PGPSecretKey)keys.get(0)).getPublicKey();
		}

		/// <summary>
		/// Return the public key referred to by the passed in keyID if it
		/// is present.
		/// </summary>
		/// <param name="keyID"> the full keyID of the key of interest. </param>
		/// <returns> PGPPublicKey with matching keyID, null if it is not present. </returns>
		public override PGPPublicKey getPublicKey(long keyID)
		{
			PGPSecretKey key = getSecretKey(keyID);
			if (key != null)
			{
				return key.getPublicKey();
			}

			for (int i = 0; i != extraPubKeys.size(); i++)
			{
				PGPPublicKey k = (PGPPublicKey)keys.get(i);

				if (keyID == k.getKeyID())
				{
					return k;
				}
			}

			return null;
		}

		/// <summary>
		/// Return the public key with the passed in fingerprint if it
		/// is present.
		/// </summary>
		/// <param name="fingerprint"> the full fingerprint of the key of interest. </param>
		/// <returns> PGPPublicKey with the matching fingerprint, null if it is not present. </returns>
		public override PGPPublicKey getPublicKey(byte[] fingerprint)
		{
			PGPSecretKey key = getSecretKey(fingerprint);
			if (key != null)
			{
				return key.getPublicKey();
			}

			for (int i = 0; i != extraPubKeys.size(); i++)
			{
				PGPPublicKey k = (PGPPublicKey)keys.get(i);

				if (Arrays.areEqual(fingerprint, k.getFingerprint()))
				{
					return k;
				}
			}

			return null;
		}

		/// <summary>
		/// Return any keys carrying a signature issued by the key represented by keyID.
		/// </summary>
		/// <param name="keyID"> the key id to be matched against. </param>
		/// <returns> an iterator (possibly empty) of PGPPublicKey objects carrying signatures from keyID. </returns>
		public override Iterator<PGPPublicKey> getKeysWithSignaturesBy(long keyID)
		{
			List keysWithSigs = new ArrayList();

			for (Iterator keyIt = getPublicKeys(); keyIt.hasNext();)
			{
				PGPPublicKey k = (PGPPublicKey)keyIt.next();

				Iterator sigIt = k.getSignaturesForKeyID(keyID);

				if (sigIt.hasNext())
				{
					keysWithSigs.add(k);
				}
			}

			return keysWithSigs.iterator();
		}

		/// <summary>
		/// Return an iterator containing all the public keys.
		/// </summary>
		/// <returns> Iterator </returns>
		public override Iterator<PGPPublicKey> getPublicKeys()
		{
			List pubKeys = new ArrayList();

			for (Iterator it = getSecretKeys(); it.hasNext();)
			{
				PGPPublicKey key = ((PGPSecretKey)it.next()).getPublicKey();
				pubKeys.add(key);
			}

			pubKeys.addAll(extraPubKeys);

			return Collections.unmodifiableList(pubKeys).iterator();
		}

		/// <summary>
		/// Return the master private key.
		/// </summary>
		/// <returns> PGPSecretKey </returns>
		public virtual PGPSecretKey getSecretKey()
		{
			return ((PGPSecretKey)keys.get(0));
		}

		/// <summary>
		/// Return an iterator containing all the secret keys.
		/// </summary>
		/// <returns> Iterator </returns>
		public virtual Iterator<PGPSecretKey> getSecretKeys()
		{
			return Collections.unmodifiableList(keys).iterator();
		}

		/// <summary>
		/// Return the secret key referred to by the passed in keyID if it
		/// is present.
		/// </summary>
		/// <param name="keyID"> the full keyID of the key of interest. </param>
		/// <returns> PGPSecretKey with matching keyID, null if it is not present. </returns>
		public virtual PGPSecretKey getSecretKey(long keyID)
		{
			for (int i = 0; i != keys.size(); i++)
			{
				PGPSecretKey k = (PGPSecretKey)keys.get(i);

				if (keyID == k.getKeyID())
				{
					return k;
				}
			}

			return null;
		}

		/// <summary>
		/// Return the secret key associated with the passed in fingerprint if it
		/// is present.
		/// </summary>
		/// <param name="fingerprint"> the full fingerprint of the key of interest. </param>
		/// <returns> PGPSecretKey with the matching fingerprint, null if it is not present. </returns>
		public virtual PGPSecretKey getSecretKey(byte[] fingerprint)
		{
			for (int i = 0; i != keys.size(); i++)
			{
				PGPSecretKey k = (PGPSecretKey)keys.get(i);

				if (Arrays.areEqual(fingerprint, k.getPublicKey().getFingerprint()))
				{
					return k;
				}
			}

			return null;
		}

		/// <summary>
		/// Return an iterator of the public keys in the secret key ring that
		/// have no matching private key. At the moment only personal certificate data
		/// appears in this fashion.
		/// </summary>
		/// <returns>  iterator of unattached, or extra, public keys. </returns>
		public virtual Iterator<PGPPublicKey> getExtraPublicKeys()
		{
			return extraPubKeys.iterator();
		}

		public override byte[] getEncoded()
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			this.encode(bOut);

			return bOut.toByteArray();
		}

		public override void encode(OutputStream outStream)
		{
			for (int i = 0; i != keys.size(); i++)
			{
				PGPSecretKey k = (PGPSecretKey)keys.get(i);

				k.encode(outStream);
			}
			for (int i = 0; i != extraPubKeys.size(); i++)
			{
				PGPPublicKey k = (PGPPublicKey)extraPubKeys.get(i);

				k.encode(outStream);
			}
		}

		/// <summary>
		/// Support method for Iterable where available.
		/// </summary>
		public virtual Iterator<PGPSecretKey> iterator()
		{
			return getSecretKeys();
		}

		/// <summary>
		/// Replace the public key set on the secret ring with the corresponding key off the public ring.
		/// </summary>
		/// <param name="secretRing"> secret ring to be changed. </param>
		/// <param name="publicRing"> public ring containing the new public key set. </param>
		public static PGPSecretKeyRing replacePublicKeys(PGPSecretKeyRing secretRing, PGPPublicKeyRing publicRing)
		{
			List newList = new ArrayList(secretRing.keys.size());

			for (Iterator it = secretRing.keys.iterator(); it.hasNext();)
			{
				PGPSecretKey sk = (PGPSecretKey)it.next();
				PGPPublicKey pk = publicRing.getPublicKey(sk.getKeyID());

				newList.add(PGPSecretKey.replacePublicKey(sk, pk));
			}

			return new PGPSecretKeyRing(newList);
		}

		/// <summary>
		/// Return a copy of the passed in secret key ring, with the private keys (where present) associated with the master key and sub keys
		/// are encrypted using a new password and the passed in algorithm.
		/// </summary>
		/// <param name="ring"> the PGPSecretKeyRing to be copied. </param>
		/// <param name="oldKeyDecryptor"> the current decryptor based on the current password for key. </param>
		/// <param name="newKeyEncryptor"> a new encryptor based on a new password for encrypting the secret key material. </param>
		/// <returns> the updated key ring. </returns>
		public static PGPSecretKeyRing copyWithNewPassword(PGPSecretKeyRing ring, PBESecretKeyDecryptor oldKeyDecryptor, PBESecretKeyEncryptor newKeyEncryptor)
		{
			List newKeys = new ArrayList(ring.keys.size());

			for (Iterator keys = ring.getSecretKeys(); keys.hasNext();)
			{
				PGPSecretKey key = (PGPSecretKey)keys.next();

				if (key.isPrivateKeyEmpty())
				{
					newKeys.add(key);
				}
				else
				{
					newKeys.add(PGPSecretKey.copyWithNewPassword(key, oldKeyDecryptor, newKeyEncryptor));
				}
			}

			return new PGPSecretKeyRing(newKeys, ring.extraPubKeys);
		}

		/// <summary>
		/// Returns a new key ring with the secret key passed in either added or
		/// replacing an existing one with the same key ID.
		/// </summary>
		/// <param name="secRing"> the secret key ring to be modified. </param>
		/// <param name="secKey"> the secret key to be added. </param>
		/// <returns> a new secret key ring. </returns>
		public static PGPSecretKeyRing insertSecretKey(PGPSecretKeyRing secRing, PGPSecretKey secKey)
		{
			List keys = new ArrayList(secRing.keys);
			bool found = false;
			bool masterFound = false;

			for (int i = 0; i != keys.size();i++)
			{
				PGPSecretKey key = (PGPSecretKey)keys.get(i);

				if (key.getKeyID() == secKey.getKeyID())
				{
					found = true;
					keys.set(i, secKey);
				}
				if (key.isMasterKey())
				{
					masterFound = true;
				}
			}

			if (!found)
			{
				if (secKey.isMasterKey())
				{
					if (masterFound)
					{
						throw new IllegalArgumentException("cannot add a master key to a ring that already has one");
					}

					keys.add(0, secKey);
				}
				else
				{
					keys.add(secKey);
				}
			}

			return new PGPSecretKeyRing(keys, secRing.extraPubKeys);
		}

		/// <summary>
		/// Returns a new key ring with the secret key passed in removed from the
		/// key ring.
		/// </summary>
		/// <param name="secRing"> the secret key ring to be modified. </param>
		/// <param name="secKey"> the secret key to be removed. </param>
		/// <returns> a new secret key ring, or null if secKey is not found. </returns>
		public static PGPSecretKeyRing removeSecretKey(PGPSecretKeyRing secRing, PGPSecretKey secKey)
		{
			List keys = new ArrayList(secRing.keys);
			bool found = false;

			for (int i = 0; i < keys.size();i++)
			{
				PGPSecretKey key = (PGPSecretKey)keys.get(i);

				if (key.getKeyID() == secKey.getKeyID())
				{
					found = true;
					keys.remove(i);
				}
			}

			if (!found)
			{
				return null;
			}

			return new PGPSecretKeyRing(keys, secRing.extraPubKeys);
		}
	}

}