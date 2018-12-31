using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{
	
	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-6.2.1">RFC 5652</a>:
	/// Content encryption key delivery mechanisms.
	/// <pre>
	/// KeyTransRecipientInfo ::= SEQUENCE {
	///     version CMSVersion,  -- always set to 0 or 2
	///     rid RecipientIdentifier,
	///     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
	///     encryptedKey EncryptedKey 
	/// }
	/// </pre>
	/// </summary>
	public class KeyTransRecipientInfo : ASN1Object
	{
		private ASN1Integer version;
		private RecipientIdentifier rid;
		private AlgorithmIdentifier keyEncryptionAlgorithm;
		private ASN1OctetString encryptedKey;

		public KeyTransRecipientInfo(RecipientIdentifier rid, AlgorithmIdentifier keyEncryptionAlgorithm, ASN1OctetString encryptedKey)
		{
			if (rid.toASN1Primitive() is ASN1TaggedObject)
			{
				this.version = new ASN1Integer(2);
			}
			else
			{
				this.version = new ASN1Integer(0);
			}

			this.rid = rid;
			this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
			this.encryptedKey = encryptedKey;
		}

		/// @deprecated use getInstance() 
		public KeyTransRecipientInfo(ASN1Sequence seq)
		{
			this.version = (ASN1Integer)seq.getObjectAt(0);
			this.rid = RecipientIdentifier.getInstance(seq.getObjectAt(1));
			this.keyEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(2));
			this.encryptedKey = (ASN1OctetString)seq.getObjectAt(3);
		}

		/// <summary>
		/// Return a KeyTransRecipientInfo object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="KeyTransRecipientInfo"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with KeyTransRecipientInfo structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static KeyTransRecipientInfo getInstance(object obj)
		{
			if (obj is KeyTransRecipientInfo)
			{
				return (KeyTransRecipientInfo)obj;
			}

			if (obj != null)
			{
				return new KeyTransRecipientInfo(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual ASN1Integer getVersion()
		{
			return version;
		}

		public virtual RecipientIdentifier getRecipientIdentifier()
		{
			return rid;
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
			v.add(rid);
			v.add(keyEncryptionAlgorithm);
			v.add(encryptedKey);

			return new DERSequence(v);
		}
	}

}