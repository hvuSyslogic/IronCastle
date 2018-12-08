using org.bouncycastle.bcpg;

namespace org.bouncycastle.openpgp
{

	using BCPGInputStream = org.bouncycastle.bcpg.BCPGInputStream;
	using PacketTags = org.bouncycastle.bcpg.PacketTags;
	using PublicKeyPacket = org.bouncycastle.bcpg.PublicKeyPacket;
	using TrustPacket = org.bouncycastle.bcpg.TrustPacket;
	using KeyFingerPrintCalculator = org.bouncycastle.openpgp.@operator.KeyFingerPrintCalculator;
	using Arrays = org.bouncycastle.util.Arrays;
	using Iterable = org.bouncycastle.util.Iterable;

	/// <summary>
	/// Class to hold a single master public key and its subkeys.
	/// <para>
	/// Often PGP keyring files consist of multiple master keys, if you are trying to process
	/// or construct one of these you should use the PGPPublicKeyRingCollection class.
	/// </para>
	/// </summary>
	public class PGPPublicKeyRing : PGPKeyRing, Iterable<PGPPublicKey>
	{
		internal List keys;

		public PGPPublicKeyRing(byte[] encoding, KeyFingerPrintCalculator fingerPrintCalculator) : this(new ByteArrayInputStream(encoding), fingerPrintCalculator)
		{
		}

		private static List checkKeys(List keys)
		{
			List rv = new ArrayList(keys.size());

			for (int i = 0; i != keys.size(); i++)
			{
				PGPPublicKey k = (PGPPublicKey)keys.get(i);

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
		/// Base constructor from a list of keys representing a public key ring (a master key and its
		/// associated sub-keys).
		/// </summary>
		/// <param name="pubKeys"> the list of keys making up the ring. </param>
		public PGPPublicKeyRing(List pubKeys)
		{
			this.keys = checkKeys(pubKeys);
		}

		public PGPPublicKeyRing(InputStream @in, KeyFingerPrintCalculator fingerPrintCalculator)
		{
			this.keys = new ArrayList();

			BCPGInputStream pIn = wrap(@in);

			int initialTag = pIn.nextPacketTag();
			if (initialTag != PacketTags_Fields.PUBLIC_KEY && initialTag != PacketTags_Fields.PUBLIC_SUBKEY)
			{
				throw new IOException("public key ring doesn't start with public key tag: " + "tag 0x" + initialTag.ToString("x"));
			}

			PublicKeyPacket pubPk = (PublicKeyPacket)pIn.readPacket();
			TrustPacket trustPk = readOptionalTrustPacket(pIn);

			// direct signatures and revocations
			List keySigs = readSignaturesAndTrust(pIn);

			List ids = new ArrayList();
			List idTrusts = new ArrayList();
			List idSigs = new ArrayList();
			readUserIDs(pIn, ids, idTrusts, idSigs);

			try
			{
				keys.add(new PGPPublicKey(pubPk, trustPk, keySigs, ids, idTrusts, idSigs, fingerPrintCalculator));

				// Read subkeys
				while (pIn.nextPacketTag() == PacketTags_Fields.PUBLIC_SUBKEY)
				{
					keys.add(readSubkey(pIn, fingerPrintCalculator));
				}
			}
			catch (PGPException e)
			{
				throw new IOException("processing exception: " + e.ToString());
			}
		}

		/// <summary>
		/// Return the first public key in the ring.
		/// </summary>
		/// <returns> PGPPublicKey </returns>
		public override PGPPublicKey getPublicKey()
		{
			return (PGPPublicKey)keys.get(0);
		}

		/// <summary>
		/// Return the public key referred to by the passed in keyID if it
		/// is present.
		/// </summary>
		/// <param name="keyID"> the full keyID of the key of interest. </param>
		/// <returns> PGPPublicKey with matching keyID, null if it is not present. </returns>
		public override PGPPublicKey getPublicKey(long keyID)
		{
			for (int i = 0; i != keys.size(); i++)
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
			for (int i = 0; i != keys.size(); i++)
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

			for (int i = 0; i != keys.size(); i++)
			{
				PGPPublicKey k = (PGPPublicKey)keys.get(i);

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
			return Collections.unmodifiableList(keys).iterator();
		}

		/// <summary>
		/// Support method for Iterable where available.
		/// </summary>
		public virtual Iterator<PGPPublicKey> iterator()
		{
			return getPublicKeys();
		}

		public override byte[] getEncoded()
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			this.encode(bOut);

			return bOut.toByteArray();
		}

		/// <summary>
		/// Return an encoding of the key ring, with trust packets stripped out if forTransfer is true.
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

		public override void encode(OutputStream outStream)
		{
			encode(outStream, false);
		}

		/// <summary>
		/// Encode the key ring to outStream, with trust packets stripped out if forTransfer is true.
		/// </summary>
		/// <param name="outStream"> stream to write the key encoding to. </param>
		/// <param name="forTransfer"> if the purpose of encoding is to send key to other users. </param>
		/// <exception cref="IOException"> in case of encoding error. </exception>
		public virtual void encode(OutputStream outStream, bool forTransfer)
		{
			for (int i = 0; i != keys.size(); i++)
			{
				PGPPublicKey k = (PGPPublicKey)keys.get(i);

				k.encode(outStream, forTransfer);
			}
		}

		/// <summary>
		/// Returns a new key ring with the public key passed in
		/// either added or replacing an existing one.
		/// </summary>
		/// <param name="pubRing"> the public key ring to be modified </param>
		/// <param name="pubKey"> the public key to be inserted. </param>
		/// <returns> a new keyRing </returns>
		public static PGPPublicKeyRing insertPublicKey(PGPPublicKeyRing pubRing, PGPPublicKey pubKey)
		{
			List keys = new ArrayList(pubRing.keys);
			bool found = false;
			bool masterFound = false;

			for (int i = 0; i != keys.size();i++)
			{
				PGPPublicKey key = (PGPPublicKey)keys.get(i);

				if (key.getKeyID() == pubKey.getKeyID())
				{
					found = true;
					keys.set(i, pubKey);
				}
				if (key.isMasterKey())
				{
					masterFound = true;
				}
			}

			if (!found)
			{
				if (pubKey.isMasterKey())
				{
					if (masterFound)
					{
						throw new IllegalArgumentException("cannot add a master key to a ring that already has one");
					}

					keys.add(0, pubKey);
				}
				else
				{
					keys.add(pubKey);
				}
			}

			return new PGPPublicKeyRing(keys);
		}

		/// <summary>
		/// Returns a new key ring with the public key passed in
		/// removed from the key ring.
		/// </summary>
		/// <param name="pubRing"> the public key ring to be modified </param>
		/// <param name="pubKey"> the public key to be removed. </param>
		/// <returns> a new keyRing, null if pubKey is not found. </returns>
		public static PGPPublicKeyRing removePublicKey(PGPPublicKeyRing pubRing, PGPPublicKey pubKey)
		{
			List keys = new ArrayList(pubRing.keys);
			bool found = false;

			for (int i = 0; i < keys.size();i++)
			{
				PGPPublicKey key = (PGPPublicKey)keys.get(i);

				if (key.getKeyID() == pubKey.getKeyID())
				{
					found = true;
					keys.remove(i);
				}
			}

			if (!found)
			{
				return null;
			}

			return new PGPPublicKeyRing(keys);
		}

		internal static PGPPublicKey readSubkey(BCPGInputStream @in, KeyFingerPrintCalculator fingerPrintCalculator)
		{
			PublicKeyPacket pk = (PublicKeyPacket)@in.readPacket();
			TrustPacket kTrust = readOptionalTrustPacket(@in);

			// PGP 8 actually leaves out the signature.
			List sigList = readSignaturesAndTrust(@in);

			return new PGPPublicKey(pk, kTrust, sigList, fingerPrintCalculator);
		}
	}

}