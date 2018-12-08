using org.bouncycastle.bcpg;

using System;

namespace org.bouncycastle.openpgp
{

	using SignaturePacket = org.bouncycastle.bcpg.SignaturePacket;
	using SignatureSubpacket = org.bouncycastle.bcpg.SignatureSubpacket;
	using SignatureSubpacketTags = org.bouncycastle.bcpg.SignatureSubpacketTags;
	using Features = org.bouncycastle.bcpg.sig.Features;
	using IssuerKeyID = org.bouncycastle.bcpg.sig.IssuerKeyID;
	using KeyExpirationTime = org.bouncycastle.bcpg.sig.KeyExpirationTime;
	using KeyFlags = org.bouncycastle.bcpg.sig.KeyFlags;
	using NotationData = org.bouncycastle.bcpg.sig.NotationData;
	using PreferredAlgorithms = org.bouncycastle.bcpg.sig.PreferredAlgorithms;
	using PrimaryUserID = org.bouncycastle.bcpg.sig.PrimaryUserID;
	using SignatureCreationTime = org.bouncycastle.bcpg.sig.SignatureCreationTime;
	using SignatureExpirationTime = org.bouncycastle.bcpg.sig.SignatureExpirationTime;
	using SignatureTarget = org.bouncycastle.bcpg.sig.SignatureTarget;
	using SignerUserID = org.bouncycastle.bcpg.sig.SignerUserID;

	/// <summary>
	/// Container for a list of signature subpackets.
	/// </summary>
	public class PGPSignatureSubpacketVector
	{
		internal SignatureSubpacket[] packets;

		public PGPSignatureSubpacketVector(SignatureSubpacket[] packets)
		{
			this.packets = packets;
		}

		public virtual SignatureSubpacket getSubpacket(int type)
		{
			for (int i = 0; i != packets.Length; i++)
			{
				if (packets[i].getType() == type)
				{
					return packets[i];
				}
			}

			return null;
		}

		/// <summary>
		/// Return true if a particular subpacket type exists.
		/// </summary>
		/// <param name="type"> type to look for. </param>
		/// <returns> true if present, false otherwise. </returns>
		public virtual bool hasSubpacket(int type)
		{
			return getSubpacket(type) != null;
		}

		/// <summary>
		/// Return all signature subpackets of the passed in type. </summary>
		/// <param name="type"> subpacket type code </param>
		/// <returns> an array of zero or more matching subpackets. </returns>
		public virtual SignatureSubpacket[] getSubpackets(int type)
		{
			List list = new ArrayList();

			for (int i = 0; i != packets.Length; i++)
			{
				if (packets[i].getType() == type)
				{
					list.add(packets[i]);
				}
			}

			return (SignatureSubpacket[])list.toArray(new SignatureSubpacket[]{});
		}

		public virtual PGPSignatureList getEmbeddedSignatures()
		{
			SignatureSubpacket[] sigs = getSubpackets(SignatureSubpacketTags_Fields.EMBEDDED_SIGNATURE);
			ArrayList l = new ArrayList();

			for (int i = 0; i < sigs.Length; i++)
			{
				try
				{
					l.add(new PGPSignature(SignaturePacket.fromByteArray(sigs[i].getData())));
				}
				catch (IOException e)
				{
					throw new PGPException("Unable to parse signature packet: " + e.Message, e);
				}
			}

			return new PGPSignatureList((PGPSignature[])l.toArray(new PGPSignature[l.size()]));
		}

		public virtual NotationData[] getNotationDataOccurrences()
		{
			SignatureSubpacket[] notations = getSubpackets(SignatureSubpacketTags_Fields.NOTATION_DATA);
			NotationData[] vals = new NotationData[notations.Length];
			for (int i = 0; i < notations.Length; i++)
			{
				vals[i] = (NotationData)notations[i];
			}

			return vals;
		}

		/// @deprecated use  getNotationDataOccurrences() 
		public virtual NotationData[] getNotationDataOccurences()
		{
			return getNotationDataOccurrences();
		}

		public virtual long getIssuerKeyID()
		{
			SignatureSubpacket p = this.getSubpacket(SignatureSubpacketTags_Fields.ISSUER_KEY_ID);

			if (p == null)
			{
				return 0;
			}

			return ((IssuerKeyID)p).getKeyID();
		}

		public virtual DateTime getSignatureCreationTime()
		{
			SignatureSubpacket p = this.getSubpacket(SignatureSubpacketTags_Fields.CREATION_TIME);

			if (p == null)
			{
				return null;
			}

			return ((SignatureCreationTime)p).getTime();
		}

		/// <summary>
		/// Return the number of seconds a signature is valid for after its creation date. A value of zero means
		/// the signature never expires.
		/// </summary>
		/// <returns> seconds a signature is valid for. </returns>
		public virtual long getSignatureExpirationTime()
		{
			SignatureSubpacket p = this.getSubpacket(SignatureSubpacketTags_Fields.EXPIRE_TIME);

			if (p == null)
			{
				return 0;
			}

			return ((SignatureExpirationTime)p).getTime();
		}

		/// <summary>
		/// Return the number of seconds a key is valid for after its creation date. A value of zero means
		/// the key never expires.
		/// </summary>
		/// <returns> seconds a key is valid for. </returns>
		public virtual long getKeyExpirationTime()
		{
			SignatureSubpacket p = this.getSubpacket(SignatureSubpacketTags_Fields.KEY_EXPIRE_TIME);

			if (p == null)
			{
				return 0;
			}

			return ((KeyExpirationTime)p).getTime();
		}

		public virtual int[] getPreferredHashAlgorithms()
		{
			SignatureSubpacket p = this.getSubpacket(SignatureSubpacketTags_Fields.PREFERRED_HASH_ALGS);

			if (p == null)
			{
				return null;
			}

			return ((PreferredAlgorithms)p).getPreferences();
		}

		public virtual int[] getPreferredSymmetricAlgorithms()
		{
			SignatureSubpacket p = this.getSubpacket(SignatureSubpacketTags_Fields.PREFERRED_SYM_ALGS);

			if (p == null)
			{
				return null;
			}

			return ((PreferredAlgorithms)p).getPreferences();
		}

		public virtual int[] getPreferredCompressionAlgorithms()
		{
			SignatureSubpacket p = this.getSubpacket(SignatureSubpacketTags_Fields.PREFERRED_COMP_ALGS);

			if (p == null)
			{
				return null;
			}

			return ((PreferredAlgorithms)p).getPreferences();
		}

		public virtual int getKeyFlags()
		{
			SignatureSubpacket p = this.getSubpacket(SignatureSubpacketTags_Fields.KEY_FLAGS);

			if (p == null)
			{
				return 0;
			}

			return ((KeyFlags)p).getFlags();
		}

		public virtual string getSignerUserID()
		{
			SignatureSubpacket p = this.getSubpacket(SignatureSubpacketTags_Fields.SIGNER_USER_ID);

			if (p == null)
			{
				return null;
			}

			return ((SignerUserID)p).getID();
		}

		public virtual bool isPrimaryUserID()
		{
			PrimaryUserID primaryId = (PrimaryUserID)this.getSubpacket(SignatureSubpacketTags_Fields.PRIMARY_USER_ID);

			if (primaryId != null)
			{
				return primaryId.isPrimaryUserID();
			}

			return false;
		}

		public virtual int[] getCriticalTags()
		{
			int count = 0;

			for (int i = 0; i != packets.Length; i++)
			{
				if (packets[i].isCritical())
				{
					count++;
				}
			}

			int[] list = new int[count];

			count = 0;

			for (int i = 0; i != packets.Length; i++)
			{
				if (packets[i].isCritical())
				{
					list[count++] = packets[i].getType();
				}
			}

			return list;
		}

		public virtual SignatureTarget getSignatureTarget()
		{
			SignatureSubpacket p = this.getSubpacket(SignatureSubpacketTags_Fields.SIGNATURE_TARGET);

			if (p == null)
			{
				return null;
			}

			return new SignatureTarget(p.isCritical(), p.isLongLength(), p.getData());
		}

		public virtual Features getFeatures()
		{
			SignatureSubpacket p = this.getSubpacket(SignatureSubpacketTags_Fields.FEATURES);

			if (p == null)
			{
				return null;
			}

			return new Features(p.isCritical(), p.isLongLength(), p.getData());
		}

		/// <summary>
		/// Return the number of packets this vector contains.
		/// </summary>
		/// <returns> size of the packet vector. </returns>
		public virtual int size()
		{
			return packets.Length;
		}

		public virtual SignatureSubpacket[] toSubpacketArray()
		{
			return packets;
		}

		/// <summary>
		/// Return a copy of the subpackets in this vector.
		/// </summary>
		/// <returns> an array containing the vector subpackets in order. </returns>
		public virtual SignatureSubpacket[] toArray()
		{
			SignatureSubpacket[] rv = new SignatureSubpacket[packets.Length];

			JavaSystem.arraycopy(packets, 0, rv, 0, rv.Length);

			return rv;
		}
	}

}