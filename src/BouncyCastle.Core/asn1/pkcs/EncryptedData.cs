using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.pkcs
{
	
	/// <summary>
	/// The EncryptedData object.
	/// <pre>
	///      EncryptedData ::= SEQUENCE {
	///           version Version,
	///           encryptedContentInfo EncryptedContentInfo
	///      }
	/// 
	/// 
	///      EncryptedContentInfo ::= SEQUENCE {
	///          contentType ContentType,
	///          contentEncryptionAlgorithm  ContentEncryptionAlgorithmIdentifier,
	///          encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
	///    }
	/// 
	///    EncryptedContent ::= OCTET STRING
	/// </pre>
	/// </summary>
	public class EncryptedData : ASN1Object
	{
		internal ASN1Sequence data;

		public static EncryptedData getInstance(object obj)
		{
			 if (obj is EncryptedData)
			 {
				 return (EncryptedData)obj;
			 }

			 if (obj != null)
			 {
				 return new EncryptedData(ASN1Sequence.getInstance(obj));
			 }

			 return null;
		}

		private EncryptedData(ASN1Sequence seq)
		{
			int version = ((ASN1Integer)seq.getObjectAt(0)).getValue().intValue();

			if (version != 0)
			{
				throw new IllegalArgumentException("sequence not version 0");
			}

			this.data = ASN1Sequence.getInstance(seq.getObjectAt(1));
		}

		public EncryptedData(ASN1ObjectIdentifier contentType, AlgorithmIdentifier encryptionAlgorithm, ASN1Encodable content)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(contentType);
			v.add(encryptionAlgorithm.toASN1Primitive());
			v.add(new BERTaggedObject(false, 0, content));

			data = new BERSequence(v);
		}

		public virtual ASN1ObjectIdentifier getContentType()
		{
			return ASN1ObjectIdentifier.getInstance(data.getObjectAt(0));
		}

		public virtual AlgorithmIdentifier getEncryptionAlgorithm()
		{
			return AlgorithmIdentifier.getInstance(data.getObjectAt(1));
		}

		public virtual ASN1OctetString getContent()
		{
			if (data.size() == 3)
			{
				ASN1TaggedObject o = ASN1TaggedObject.getInstance(data.getObjectAt(2));

				return ASN1OctetString.getInstance(o, false);
			}

			return null;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(new ASN1Integer(0));
			v.add(data);

			return new BERSequence(v);
		}
	}

}