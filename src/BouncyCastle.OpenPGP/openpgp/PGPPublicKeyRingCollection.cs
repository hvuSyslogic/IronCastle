using System;

namespace org.bouncycastle.openpgp
{

	using BCPGOutputStream = org.bouncycastle.bcpg.BCPGOutputStream;
	using KeyFingerPrintCalculator = org.bouncycastle.openpgp.@operator.KeyFingerPrintCalculator;
	using Iterable = org.bouncycastle.util.Iterable;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// Often a PGP key ring file is made up of a succession of master/sub-key key rings.
	/// If you want to read an entire public key file in one hit this is the class for you.
	/// </summary>
	public class PGPPublicKeyRingCollection : Iterable<PGPPublicKeyRing>
	{
		private Map pubRings = new HashMap();
		private List order = new ArrayList();

		private PGPPublicKeyRingCollection(Map pubRings, List order)
		{
			this.pubRings = pubRings;
			this.order = order;
		}

		public PGPPublicKeyRingCollection(byte[] encoding, KeyFingerPrintCalculator fingerPrintCalculator) : this(new ByteArrayInputStream(encoding), fingerPrintCalculator)
		{
		}

		/// <summary>
		/// Build a PGPPublicKeyRingCollection from the passed in input stream.
		/// </summary>
		/// <param name="in">  input stream containing data </param>
		/// <exception cref="IOException"> if a problem parsing the base stream occurs </exception>
		/// <exception cref="PGPException"> if an object is encountered which isn't a PGPPublicKeyRing </exception>
		public PGPPublicKeyRingCollection(InputStream @in, KeyFingerPrintCalculator fingerPrintCalculator)
		{
			PGPObjectFactory pgpFact = new PGPObjectFactory(@in, fingerPrintCalculator);
			object obj;

			while ((obj = pgpFact.nextObject()) != null)
			{
				if (!(obj is PGPPublicKeyRing))
				{
					throw new PGPException(obj.GetType().getName() + " found where PGPPublicKeyRing expected");
				}

				PGPPublicKeyRing pgpPub = (PGPPublicKeyRing)obj;
				long? key = new long?(pgpPub.getPublicKey().getKeyID());

				pubRings.put(key, pgpPub);
				order.add(key);
			}
		}

		public PGPPublicKeyRingCollection(Collection<PGPPublicKeyRing> collection)
		{
			Iterator it = collection.iterator();

			while (it.hasNext())
			{
				PGPPublicKeyRing pgpPub = (PGPPublicKeyRing)it.next();

				long? key = new long?(pgpPub.getPublicKey().getKeyID());

				pubRings.put(key, pgpPub);
				order.add(key);
			}
		}

		/// <summary>
		/// Return the number of rings in this collection.
		/// </summary>
		/// <returns> size of the collection </returns>
		public virtual int size()
		{
			return order.size();
		}

		/// <summary>
		/// return the public key rings making up this collection.
		/// </summary>
		public virtual Iterator<PGPPublicKeyRing> getKeyRings()
		{
			return pubRings.values().iterator();
		}

		/// <summary>
		/// Return an iterator of the key rings associated with the passed in userID.
		/// </summary>
		/// <param name="userID"> the user ID to be matched. </param>
		/// <returns> an iterator (possibly empty) of key rings which matched. </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual Iterator<PGPPublicKeyRing> getKeyRings(string userID)
		{
			return getKeyRings(userID, false, false);
		}

		/// <summary>
		/// Return an iterator of the key rings associated with the passed in userID.
		/// <para>
		/// 
		/// </para>
		/// </summary>
		/// <param name="userID"> the user ID to be matched. </param>
		/// <param name="matchPartial"> if true userID need only be a substring of an actual ID string to match. </param>
		/// <returns> an iterator (possibly empty) of key rings which matched. </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual Iterator<PGPPublicKeyRing> getKeyRings(string userID, bool matchPartial)
		{
			return getKeyRings(userID, matchPartial, false);
		}

		/// <summary>
		/// Return an iterator of the key rings associated with the passed in userID.
		/// <para>
		/// 
		/// </para>
		/// </summary>
		/// <param name="userID"> the user ID to be matched. </param>
		/// <param name="matchPartial"> if true userID need only be a substring of an actual ID string to match. </param>
		/// <param name="ignoreCase"> if true case is ignored in user ID comparisons. </param>
		/// <returns> an iterator (possibly empty) of key rings which matched. </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual Iterator<PGPPublicKeyRing> getKeyRings(string userID, bool matchPartial, bool ignoreCase)
		{
			Iterator it = this.getKeyRings();
			List rings = new ArrayList();

			if (ignoreCase)
			{
				userID = Strings.toLowerCase(userID);
			}

			while (it.hasNext())
			{
				PGPPublicKeyRing pubRing = (PGPPublicKeyRing)it.next();
				Iterator uIt = pubRing.getPublicKey().getUserIDs();

				while (uIt.hasNext())
				{
					string next = (string)uIt.next();
					if (ignoreCase)
					{
						next = Strings.toLowerCase(next);
					}

					if (matchPartial)
					{
						if (next.IndexOf(userID, StringComparison.Ordinal) > -1)
						{
							rings.add(pubRing);
						}
					}
					else
					{
						if (next.Equals(userID))
						{
							rings.add(pubRing);
						}
					}
				}
			}

			return rings.iterator();
		}

		/// <summary>
		/// Return the PGP public key associated with the given key id.
		/// </summary>
		/// <param name="keyID"> </param>
		/// <returns> the PGP public key </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual PGPPublicKey getPublicKey(long keyID)
		{
			Iterator it = this.getKeyRings();

			while (it.hasNext())
			{
				PGPPublicKeyRing pubRing = (PGPPublicKeyRing)it.next();
				PGPPublicKey pub = pubRing.getPublicKey(keyID);

				if (pub != null)
				{
					return pub;
				}
			}

			return null;
		}

		/// <summary>
		/// Return the public key ring which contains the key referred to by keyID.
		/// </summary>
		/// <param name="keyID"> key ID to match against </param>
		/// <returns> the public key ring </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual PGPPublicKeyRing getPublicKeyRing(long keyID)
		{
			long? id = new long?(keyID);

			if (pubRings.containsKey(id))
			{
				return (PGPPublicKeyRing)pubRings.get(id);
			}

			Iterator it = this.getKeyRings();

			while (it.hasNext())
			{
				PGPPublicKeyRing pubRing = (PGPPublicKeyRing)it.next();
				PGPPublicKey pub = pubRing.getPublicKey(keyID);

				if (pub != null)
				{
					return pubRing;
				}
			}

			return null;
		}

		/// <summary>
		/// Return the PGP public key associated with the given key fingerprint.
		/// </summary>
		/// <param name="fingerprint"> the public key fingerprint to match against. </param>
		/// <returns> the PGP public key matching fingerprint. </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual PGPPublicKey getPublicKey(byte[] fingerprint)
		{
			Iterator it = this.getKeyRings();

			while (it.hasNext())
			{
				PGPPublicKeyRing pubRing = (PGPPublicKeyRing)it.next();
				PGPPublicKey pub = pubRing.getPublicKey(fingerprint);

				if (pub != null)
				{
					return pub;
				}
			}

			return null;
		}

		/// <summary>
		/// Return the PGP public key associated with the given key fingerprint.
		/// </summary>
		/// <param name="fingerprint"> the public key fingerprint to match against. </param>
		/// <returns> the PGP public key ring containing the PGP public key matching fingerprint. </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual PGPPublicKeyRing getPublicKeyRing(byte[] fingerprint)
		{
			Iterator it = this.getKeyRings();

			while (it.hasNext())
			{
				PGPPublicKeyRing pubRing = (PGPPublicKeyRing)it.next();
				PGPPublicKey pub = pubRing.getPublicKey(fingerprint);

				if (pub != null)
				{
					return pubRing;
				}
			}

			return null;
		}

		/// <summary>
		/// Return any keys carrying a signature issued by the key represented by keyID.
		/// </summary>
		/// <param name="keyID"> the key id to be matched against. </param>
		/// <returns> an iterator (possibly empty) of PGPPublicKey objects carrying signatures from keyID. </returns>
		public virtual Iterator<PGPPublicKey> getKeysWithSignaturesBy(long keyID)
		{
			List keysWithSigs = new ArrayList();

			for (Iterator it = this.iterator(); it.hasNext();)
			{
				PGPPublicKeyRing k = (PGPPublicKeyRing)it.next();

				for (Iterator keyIt = k.getKeysWithSignaturesBy(keyID); keyIt.hasNext();)
				{
					keysWithSigs.add(keyIt.next());
				}
			}

			return keysWithSigs.iterator();
		}

		/// <summary>
		/// Return true if a key matching the passed in key ID is present, false otherwise.
		/// </summary>
		/// <param name="keyID"> key ID to look for. </param>
		/// <returns> true if keyID present, false otherwise. </returns>
		public virtual bool contains(long keyID)
		{
			return getPublicKey(keyID) != null;
		}

		/// <summary>
		/// Return true if a key matching the passed in fingerprint is present, false otherwise.
		/// </summary>
		/// <param name="fingerprint"> hte key fingerprint to look for. </param>
		/// <returns> true if keyID present, false otherwise. </returns>
		public virtual bool contains(byte[] fingerprint)
		{
			return getPublicKey(fingerprint) != null;
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

			Iterator it = order.iterator();
			while (it.hasNext())
			{
				PGPPublicKeyRing sr = (PGPPublicKeyRing)pubRings.get(it.next());

				sr.encode(@out);
			}
		}


		/// <summary>
		/// Return a new collection object containing the contents of the passed in collection and
		/// the passed in public key ring.
		/// </summary>
		/// <param name="ringCollection"> the collection the ring to be added to. </param>
		/// <param name="publicKeyRing"> the key ring to be added. </param>
		/// <returns> a new collection merging the current one with the passed in ring. </returns>
		/// <exception cref="IllegalArgumentException"> if the keyID for the passed in ring is already present. </exception>
		public static PGPPublicKeyRingCollection addPublicKeyRing(PGPPublicKeyRingCollection ringCollection, PGPPublicKeyRing publicKeyRing)
		{
			long? key = new long?(publicKeyRing.getPublicKey().getKeyID());

			if (ringCollection.pubRings.containsKey(key))
			{
				throw new IllegalArgumentException("Collection already contains a key with a keyID for the passed in ring.");
			}

			Map newPubRings = new HashMap(ringCollection.pubRings);
			List newOrder = new ArrayList(ringCollection.order);

			newPubRings.put(key, publicKeyRing);
			newOrder.add(key);

			return new PGPPublicKeyRingCollection(newPubRings, newOrder);
		}

		/// <summary>
		/// Return a new collection object containing the contents of this collection with
		/// the passed in public key ring removed.
		/// </summary>
		/// <param name="ringCollection"> the collection the ring to be removed from. </param>
		/// <param name="publicKeyRing"> the key ring to be removed. </param>
		/// <returns> a new collection not containing the passed in ring. </returns>
		/// <exception cref="IllegalArgumentException"> if the keyID for the passed in ring not present. </exception>
		public static PGPPublicKeyRingCollection removePublicKeyRing(PGPPublicKeyRingCollection ringCollection, PGPPublicKeyRing publicKeyRing)
		{
			long? key = new long?(publicKeyRing.getPublicKey().getKeyID());

			if (!ringCollection.pubRings.containsKey(key))
			{
				throw new IllegalArgumentException("Collection does not contain a key with a keyID for the passed in ring.");
			}

			Map newPubRings = new HashMap(ringCollection.pubRings);
			List newOrder = new ArrayList(ringCollection.order);

			newPubRings.remove(key);

			for (int i = 0; i < newOrder.size(); i++)
			{
				long? r = (long?)newOrder.get(i);

				if (r.Value == key.Value)
				{
					newOrder.remove(i);
					break;
				}
			}

			return new PGPPublicKeyRingCollection(newPubRings, newOrder);
		}

		/// <summary>
		/// Support method for Iterable where available.
		/// </summary>
		public virtual Iterator<PGPPublicKeyRing> iterator()
		{
			return pubRings.values().iterator();
		}
	}

}