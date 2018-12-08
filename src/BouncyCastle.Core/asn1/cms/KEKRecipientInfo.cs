using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-6.2.3">RFC 5652</a>:
	/// Content encryption key delivery mechanisms.
	/// <para>
	/// <pre>
	/// KEKRecipientInfo ::= SEQUENCE {
	///     version CMSVersion,  -- always set to 4
	///     kekid KEKIdentifier,
	///     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
	///     encryptedKey EncryptedKey 
	/// }
	/// </pre>
	/// </para>
	/// </summary>
	public class KEKRecipientInfo : ASN1Object
	{
		private ASN1Integer version;
		private KEKIdentifier kekid;
		private AlgorithmIdentifier keyEncryptionAlgorithm;
		private ASN1OctetString encryptedKey;

		public KEKRecipientInfo(KEKIdentifier kekid, AlgorithmIdentifier keyEncryptionAlgorithm, ASN1OctetString encryptedKey)
		{
			this.version = new ASN1Integer(4);
			this.kekid = kekid;
			this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
			this.encryptedKey = encryptedKey;
		}

		public KEKRecipientInfo(ASN1Sequence seq)
		{
			version = (ASN1Integer)seq.getObjectAt(0);
			kekid = KEKIdentifier.getInstance(seq.getObjectAt(1));
			keyEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(2));
			encryptedKey = (ASN1OctetString)seq.getObjectAt(3);
		}

		/// <summary>
		/// Return a KEKRecipientInfo object from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want. </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the object held by the
		///          tagged object cannot be converted. </exception>
		public static KEKRecipientInfo getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Return a KEKRecipientInfo object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="KEKRecipientInfo"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with KEKRecipientInfo structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static KEKRecipientInfo getInstance(object obj)
		{
			if (obj is KEKRecipientInfo)
			{
				return (KEKRecipientInfo)obj;
			}

			if (obj != null)
			{
				return new KEKRecipientInfo(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual ASN1Integer getVersion()
		{
			return version;
		}

		public virtual KEKIdentifier getKekid()
		{
			return kekid;
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
			v.add(kekid);
			v.add(keyEncryptionAlgorithm);
			v.add(encryptedKey);

			return new DERSequence(v);
		}
	}

}