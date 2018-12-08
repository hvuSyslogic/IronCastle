using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509
{


	/// <summary>
	/// The extendedKeyUsage object.
	/// <pre>
	///      extendedKeyUsage ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
	/// </pre>
	/// </summary>
	public class ExtendedKeyUsage : ASN1Object
	{
		internal Hashtable usageTable = new Hashtable();
		internal ASN1Sequence seq;

		/// <summary>
		/// Return an ExtendedKeyUsage from the passed in tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object containing the ExtendedKeyUsage </param>
		/// <param name="explicit"> true if the tagged object should be interpreted as explicitly tagged, false if implicit. </param>
		/// <returns> the ExtendedKeyUsage contained. </returns>
		public static ExtendedKeyUsage getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Return an ExtendedKeyUsage from the passed in object.
		/// </summary>
		/// <param name="obj"> an ExtendedKeyUsage, some form or encoding of one, or null. </param>
		/// <returns>  an ExtendedKeyUsage object, or null if null is passed in. </returns>
		public static ExtendedKeyUsage getInstance(object obj)
		{
			if (obj is ExtendedKeyUsage)
			{
				return (ExtendedKeyUsage)obj;
			}
			else if (obj != null)
			{
				return new ExtendedKeyUsage(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		/// <summary>
		/// Retrieve an ExtendedKeyUsage for a passed in Extensions object, if present.
		/// </summary>
		/// <param name="extensions"> the extensions object to be examined. </param>
		/// <returns>  the ExtendedKeyUsage, null if the extension is not present. </returns>
		public static ExtendedKeyUsage fromExtensions(Extensions extensions)
		{
			return ExtendedKeyUsage.getInstance(extensions.getExtensionParsedValue(Extension.extendedKeyUsage));
		}

		/// <summary>
		/// Base constructor, from a single KeyPurposeId.
		/// </summary>
		/// <param name="usage"> the keyPurposeId to be included. </param>
		public ExtendedKeyUsage(KeyPurposeId usage)
		{
			this.seq = new DERSequence(usage);

			this.usageTable.put(usage, usage);
		}

		private ExtendedKeyUsage(ASN1Sequence seq)
		{
			this.seq = seq;

			Enumeration e = seq.getObjects();

			while (e.hasMoreElements())
			{
				ASN1Encodable o = (ASN1Encodable)e.nextElement();
				if (!(o.toASN1Primitive() is ASN1ObjectIdentifier))
				{
					throw new IllegalArgumentException("Only ASN1ObjectIdentifiers allowed in ExtendedKeyUsage.");
				}
				this.usageTable.put(o, o);
			}
		}

		/// <summary>
		/// Base constructor, from multiple KeyPurposeIds.
		/// </summary>
		/// <param name="usages"> an array of KeyPurposeIds. </param>
		public ExtendedKeyUsage(KeyPurposeId[] usages)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			for (int i = 0; i != usages.Length; i++)
			{
				v.add(usages[i]);
				this.usageTable.put(usages[i], usages[i]);
			}

			this.seq = new DERSequence(v);
		}

		/// @deprecated use KeyPurposeId[] constructor. 
		public ExtendedKeyUsage(Vector usages)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			Enumeration e = usages.elements();

			while (e.hasMoreElements())
			{
				KeyPurposeId o = KeyPurposeId.getInstance(e.nextElement());

				v.add(o);
				this.usageTable.put(o, o);
			}

			this.seq = new DERSequence(v);
		}

		/// <summary>
		/// Return true if this ExtendedKeyUsage object contains the passed in keyPurposeId.
		/// </summary>
		/// <param name="keyPurposeId">  the KeyPurposeId of interest. </param>
		/// <returns> true if the keyPurposeId is present, false otherwise. </returns>
		public virtual bool hasKeyPurposeId(KeyPurposeId keyPurposeId)
		{
			return (usageTable.get(keyPurposeId) != null);
		}

		/// <summary>
		/// Returns all extended key usages.
		/// </summary>
		/// <returns> An array with all key purposes. </returns>
		public virtual KeyPurposeId[] getUsages()
		{
			KeyPurposeId[] temp = new KeyPurposeId[seq.size()];

			int i = 0;
			for (Enumeration it = seq.getObjects(); it.hasMoreElements();)
			{
				temp[i++] = KeyPurposeId.getInstance(it.nextElement());
			}
			return temp;
		}

		/// <summary>
		/// Return the number of KeyPurposeIds present in this ExtendedKeyUsage.
		/// </summary>
		/// <returns> the number of KeyPurposeIds </returns>
		public virtual int size()
		{
			return usageTable.size();
		}

		/// <summary>
		/// Return the ASN.1 primitive form of this object.
		/// </summary>
		/// <returns> an ASN1Sequence. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return seq;
		}
	}

}