using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-10.2.7">RFC 5652</a>:
	/// Content encryption key delivery mechanisms.
	/// <pre>
	/// PasswordRecipientInfo ::= SEQUENCE {
	///     version       CMSVersion,   -- Always set to 0
	///     keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
	///                             OPTIONAL,
	///     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
	///     encryptedKey  EncryptedKey }
	/// </pre>
	/// </summary>
	public class PasswordRecipientInfo : ASN1Object
	{
		private ASN1Integer version;
		private AlgorithmIdentifier keyDerivationAlgorithm;
		private AlgorithmIdentifier keyEncryptionAlgorithm;
		private ASN1OctetString encryptedKey;

		public PasswordRecipientInfo(AlgorithmIdentifier keyEncryptionAlgorithm, ASN1OctetString encryptedKey)
		{
			this.version = new ASN1Integer(0);
			this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
			this.encryptedKey = encryptedKey;
		}

		public PasswordRecipientInfo(AlgorithmIdentifier keyDerivationAlgorithm, AlgorithmIdentifier keyEncryptionAlgorithm, ASN1OctetString encryptedKey)
		{
			this.version = new ASN1Integer(0);
			this.keyDerivationAlgorithm = keyDerivationAlgorithm;
			this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
			this.encryptedKey = encryptedKey;
		}

		/// @deprecated use getInstance() method. 
		public PasswordRecipientInfo(ASN1Sequence seq)
		{
			version = (ASN1Integer)seq.getObjectAt(0);
			if (seq.getObjectAt(1) is ASN1TaggedObject)
			{
				keyDerivationAlgorithm = AlgorithmIdentifier.getInstance((ASN1TaggedObject)seq.getObjectAt(1), false);
				keyEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(2));
				encryptedKey = (ASN1OctetString)seq.getObjectAt(3);
			}
			else
			{
				keyEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
				encryptedKey = (ASN1OctetString)seq.getObjectAt(2);
			}
		}

		/// <summary>
		/// Return a PasswordRecipientInfo object from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want. </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the object held by the
		///          tagged object cannot be converted. </exception>
		public static PasswordRecipientInfo getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Return a PasswordRecipientInfo object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="PasswordRecipientInfo"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with PasswordRecipientInfo structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static PasswordRecipientInfo getInstance(object obj)
		{
			if (obj is PasswordRecipientInfo)
			{
				return (PasswordRecipientInfo)obj;
			}

			if (obj != null)
			{
				return new PasswordRecipientInfo(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual ASN1Integer getVersion()
		{
			return version;
		}

		public virtual AlgorithmIdentifier getKeyDerivationAlgorithm()
		{
			return keyDerivationAlgorithm;
		}

		public virtual AlgorithmIdentifier getKeyEncryptionAlgorithm()
		{
			return keyEncryptionAlgorithm;
		}

		public virtual ASN1OctetString getEncryptedKey()
		{
			return encryptedKey;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(version);

			if (keyDerivationAlgorithm != null)
			{
				v.add(new DERTaggedObject(false, 0, keyDerivationAlgorithm));
			}
			v.add(keyEncryptionAlgorithm);
			v.add(encryptedKey);

			return new DERSequence(v);
		}
	}

}