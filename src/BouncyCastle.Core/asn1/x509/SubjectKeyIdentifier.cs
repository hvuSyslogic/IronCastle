using org.bouncycastle.util;

namespace org.bouncycastle.asn1.x509
{
	
	/// <summary>
	/// The SubjectKeyIdentifier object.
	/// <pre>
	/// SubjectKeyIdentifier::= OCTET STRING
	/// </pre>
	/// </summary>
	public class SubjectKeyIdentifier : ASN1Object
	{
		private byte[] keyidentifier;

		public static SubjectKeyIdentifier getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1OctetString.getInstance(obj, @explicit));
		}

		public static SubjectKeyIdentifier getInstance(object obj)
		{
			if (obj is SubjectKeyIdentifier)
			{
				return (SubjectKeyIdentifier)obj;
			}
			else if (obj != null)
			{
				return new SubjectKeyIdentifier(ASN1OctetString.getInstance(obj));
			}

			return null;
		}

		public static SubjectKeyIdentifier fromExtensions(Extensions extensions)
		{
			return SubjectKeyIdentifier.getInstance(extensions.getExtensionParsedValue(Extension.subjectKeyIdentifier));
		}

		public SubjectKeyIdentifier(byte[] keyid)
		{
			this.keyidentifier = Arrays.clone(keyid);
		}

		public SubjectKeyIdentifier(ASN1OctetString keyid) : this(keyid.getOctets())
		{
		}

		public virtual byte[] getKeyIdentifier()
		{
			return Arrays.clone(keyidentifier);
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return new DEROctetString(getKeyIdentifier());
		}
	}

}