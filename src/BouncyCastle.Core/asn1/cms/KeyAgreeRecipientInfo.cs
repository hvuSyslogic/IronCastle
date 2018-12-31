using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{
	
	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-6.2.2">RFC 5652</a>:
	/// Content encryption key delivery mechanisms.
	/// <para>
	/// <pre>
	/// KeyAgreeRecipientInfo ::= SEQUENCE {
	///     version CMSVersion,  -- always set to 3
	///     originator [0] EXPLICIT OriginatorIdentifierOrKey,
	///     ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
	///     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
	///     recipientEncryptedKeys RecipientEncryptedKeys 
	/// }
	/// 
	/// UserKeyingMaterial ::= OCTET STRING
	/// </pre>
	/// </para>
	/// </summary>
	public class KeyAgreeRecipientInfo : ASN1Object
	{
		private ASN1Integer version;
		private OriginatorIdentifierOrKey originator;
		private ASN1OctetString ukm;
		private AlgorithmIdentifier keyEncryptionAlgorithm;
		private ASN1Sequence recipientEncryptedKeys;

		public KeyAgreeRecipientInfo(OriginatorIdentifierOrKey originator, ASN1OctetString ukm, AlgorithmIdentifier keyEncryptionAlgorithm, ASN1Sequence recipientEncryptedKeys)
		{
			this.version = new ASN1Integer(3);
			this.originator = originator;
			this.ukm = ukm;
			this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
			this.recipientEncryptedKeys = recipientEncryptedKeys;
		}

		/// @deprecated use getInstance() 
		public KeyAgreeRecipientInfo(ASN1Sequence seq)
		{
			int index = 0;

			version = (ASN1Integer)seq.getObjectAt(index++);
			originator = OriginatorIdentifierOrKey.getInstance((ASN1TaggedObject)seq.getObjectAt(index++), true);

			if (seq.getObjectAt(index) is ASN1TaggedObject)
			{
				ukm = ASN1OctetString.getInstance((ASN1TaggedObject)seq.getObjectAt(index++), true);
			}

			keyEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(index++));

			recipientEncryptedKeys = (ASN1Sequence)seq.getObjectAt(index++);
		}

		/// <summary>
		/// Return a KeyAgreeRecipientInfo object from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want. </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the object held by the
		///          tagged object cannot be converted. </exception>
		public static KeyAgreeRecipientInfo getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Return a KeyAgreeRecipientInfo object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="KeyAgreeRecipientInfo"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with KeyAgreeRecipientInfo structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static KeyAgreeRecipientInfo getInstance(object obj)
		{
			if (obj is KeyAgreeRecipientInfo)
			{
				return (KeyAgreeRecipientInfo)obj;
			}

			if (obj != null)
			{
				return new KeyAgreeRecipientInfo(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual ASN1Integer getVersion()
		{
			return version;
		}

		public virtual OriginatorIdentifierOrKey getOriginator()
		{
			return originator;
		}

		public virtual ASN1OctetString getUserKeyingMaterial()
		{
			return ukm;
		}

		public virtual AlgorithmIdentifier getKeyEncryptionAlgorithm()
		{
			return keyEncryptionAlgorithm;
		}

		public virtual ASN1Sequence getRecipientEncryptedKeys()
		{
			return recipientEncryptedKeys;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(version);
			v.add(new DERTaggedObject(true, 0, originator));

			if (ukm != null)
			{
				v.add(new DERTaggedObject(true, 1, ukm));
			}

			v.add(keyEncryptionAlgorithm);
			v.add(recipientEncryptedKeys);

			return new DERSequence(v);
		}
	}

}