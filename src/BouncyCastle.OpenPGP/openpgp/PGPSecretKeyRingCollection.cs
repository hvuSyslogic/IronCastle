using System;

namespace org.bouncycastle.openpgp
{

	using BCPGOutputStream = org.bouncycastle.bcpg.BCPGOutputStream;
	using KeyFingerPrintCalculator = org.bouncycastle.openpgp.@operator.KeyFingerPrintCalculator;
	using Strings = org.bouncycastle.util.Strings;
	using Iterable = org.bouncycastle.util.Iterable;

	/// <summary>
	/// Often a PGP key ring file is made up of a succession of master/sub-key key rings.
	/// If you want to read an entire secret key file in one hit this is the class for you.
	/// </summary>
	public class PGPSecretKeyRingCollection : Iterable<PGPSecretKeyRing>
	{
		private Map secretRings = new HashMap();
		private List order = new ArrayList();

		private PGPSecretKeyRingCollection(Map secretRings, List order)
		{
			this.secretRings = secretRings;
			this.order = order;
		}

		public PGPSecretKeyRingCollection(byte[] encoding, KeyFingerPrintCalculator fingerPrintCalculator) : this(new ByteArrayInputStream(encoding), fingerPrintCalculator)
		{
		}

		/// <summary>
		/// Build a PGPSecretKeyRingCollection from the passed in input stream.
		/// </summary>
		/// <param name="in">  input stream containing data </param>
		/// <exception cref="IOException"> if a problem parsing the base stream occurs </exception>
		/// <exception cref="PGPException"> if an object is encountered which isn't a PGPSecretKeyRing </exception>
		public PGPSecretKeyRingCollection(InputStream @in, KeyFingerPrintCalculator fingerPrintCalculator)
		{
			PGPObjectFactory pgpFact = new PGPObjectFactory(@in, fingerPrintCalculator);
			object obj;

			while ((obj = pgpFact.nextObject()) != null)
			{
				if (!(obj is PGPSecretKeyRing))
				{
					throw new PGPException(obj.GetType().getName() + " found where PGPSecretKeyRing expected");
				}

				PGPSecretKeyRing pgpSecret = (PGPSecretKeyRing)obj;
				long? key = new long?(pgpSecret.getPublicKey().getKeyID());

				secretRings.put(key, pgpSecret);
				order.add(key);
			}
		}

		public PGPSecretKeyRingCollection(Collection<PGPSecretKeyRing> collection)
		{
			Iterator it = collection.iterator();

			while (it.hasNext())
			{
				PGPSecretKeyRing pgpSecret = (PGPSecretKeyRing)it.next();
				long? key = new long?(pgpSecret.getPublicKey().getKeyID());

				secretRings.put(key, pgpSecret);
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
		/// return the secret key rings making up this collection.
		/// </summary>
		public virtual Iterator<PGPSecretKeyRing> getKeyRings()
		{
			return secretRings.values().iterator();
		}

		/// <summary>
		/// Return an iterator of the key rings associated with the passed in userID.
		/// </summary>
		/// <param name="userID"> the user ID to be matched. </param>
		/// <returns> an iterator (possibly empty) of key rings which matched. </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual Iterator<PGPSecretKeyRing> getKeyRings(string userID)
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
		public virtual Iterator<PGPSecretKeyRing> getKeyRings(string userID, bool matchPartial)
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
		public virtual Iterator<PGPSecretKeyRing> getKeyRings(string userID, bool matchPartial, bool ignoreCase)
		{
			Iterator it = this.getKeyRings();
			List rings = new ArrayList();

			if (ignoreCase)
			{
				userID = Strings.toLowerCase(userID);
			}

			while (it.hasNext())
			{
				PGPSecretKeyRing secRing = (PGPSecretKeyRing)it.next();
				Iterator uIt = secRing.getSecretKey().getUserIDs();

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
							rings.add(secRing);
						}
					}
					else
					{
						if (next.Equals(userID))
						{
							rings.add(secRing);
						}
					}
				}
			}

			return rings.iterator();
		}

		/// <summary>
		/// Return the PGP secret key associated with the given key id.
		/// </summary>
		/// <param name="keyID"> </param>
		/// <returns> the secret key </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual PGPSecretKey getSecretKey(long keyID)
		{
			Iterator it = this.getKeyRings();

			while (it.hasNext())
			{
				PGPSecretKeyRing secRing = (PGPSecretKeyRing)it.next();
				PGPSecretKey sec = secRing.getSecretKey(keyID);

				if (sec != null)
				{
					return sec;
				}
			}

			return null;
		}

		/// <summary>
		/// Return the secret key ring which contains the key referred to by keyID.
		/// </summary>
		/// <param name="keyID"> </param>
		/// <returns> the secret key ring </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual PGPSecretKeyRing getSecretKeyRing(long keyID)
		{
			long? id = new long?(keyID);

			if (secretRings.containsKey(id))
			{
				return (PGPSecretKeyRing)secretRings.get(id);
			}

			Iterator it = this.getKeyRings();

			while (it.hasNext())
			{
				PGPSecretKeyRing secretRing = (PGPSecretKeyRing)it.next();
				PGPSecretKey secret = secretRing.getSecretKey(keyID);

				if (secret != null)
				{
					return secretRing;
				}
			}

			return null;
		}

		/// <summary>
		/// Return true if a key matching the passed in key ID is present, false otherwise.
		/// </summary>
		/// <param name="keyID"> key ID to look for. </param>
		/// <returns> true if keyID present, false otherwise. </returns>
		public virtual bool contains(long keyID)
		{
			return getSecretKey(keyID) != null;
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
				PGPSecretKeyRing sr = (PGPSecretKeyRing)secretRings.get(it.next());

				sr.encode(@out);
			}
		}

		/// <summary>
		/// Return a new collection object containing the contents of the passed in collection and
		/// the passed in secret key ring.
		/// </summary>
		/// <param name="ringCollection"> the collection the ring to be added to. </param>
		/// <param name="secretKeyRing"> the key ring to be added. </param>
		/// <returns> a new collection merging the current one with the passed in ring. </returns>
		/// <exception cref="IllegalArgumentException"> if the keyID for the passed in ring is already present. </exception>
		public static PGPSecretKeyRingCollection addSecretKeyRing(PGPSecretKeyRingCollection ringCollection, PGPSecretKeyRing secretKeyRing)
		{
			long? key = new long?(secretKeyRing.getPublicKey().getKeyID());

			if (ringCollection.secretRings.containsKey(key))
			{
				throw new IllegalArgumentException("Collection already contains a key with a keyID for the passed in ring.");
			}

			Map newSecretRings = new HashMap(ringCollection.secretRings);
			List newOrder = new ArrayList(ringCollection.order);

			newSecretRings.put(key, secretKeyRing);
			newOrder.add(key);

			return new PGPSecretKeyRingCollection(newSecretRings, newOrder);
		}

		/// <summary>
		/// Return a new collection object containing the contents of this collection with
		/// the passed in secret key ring removed.
		/// </summary>
		/// <param name="ringCollection"> the collection the ring to be removed from. </param>
		/// <param name="secretKeyRing"> the key ring to be removed. </param>
		/// <returns> a new collection merging the current one with the passed in ring. </returns>
		/// <exception cref="IllegalArgumentException"> if the keyID for the passed in ring is not present. </exception>
		public static PGPSecretKeyRingCollection removeSecretKeyRing(PGPSecretKeyRingCollection ringCollection, PGPSecretKeyRing secretKeyRing)
		{
			long? key = new long?(secretKeyRing.getPublicKey().getKeyID());

			if (!ringCollection.secretRings.containsKey(key))
			{
				throw new IllegalArgumentException("Collection does not contain a key with a keyID for the passed in ring.");
			}

			Map newSecretRings = new HashMap(ringCollection.secretRings);
			List newOrder = new ArrayList(ringCollection.order);

			newSecretRings.remove(key);

			for (int i = 0; i < newOrder.size(); i++)
			{
				long? r = (long?)newOrder.get(i);

				if (r.Value == key.Value)
				{
					newOrder.remove(i);
					break;
				}
			}

			return new PGPSecretKeyRingCollection(newSecretRings, newOrder);
		}

		/// <summary>
		/// Support method for Iterable where available.
		/// </summary>
		public virtual Iterator<PGPSecretKeyRing> iterator()
		{
			return secretRings.values().iterator();
		}
	}

}