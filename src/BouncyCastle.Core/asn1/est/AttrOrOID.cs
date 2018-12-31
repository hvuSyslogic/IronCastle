using System.IO;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.est
{

	
	/// <summary>
	/// <pre>
	///    AttrOrOID ::= CHOICE (oid OBJECT IDENTIFIER, attribute Attribute }
	/// </pre>
	/// </summary>
	public class AttrOrOID : ASN1Object, ASN1Choice
	{
		private readonly ASN1ObjectIdentifier oid;
		private readonly Attribute attribute;

		public AttrOrOID(ASN1ObjectIdentifier oid)
		{
			this.oid = oid;
			attribute = null;
		}

		public AttrOrOID(Attribute attribute)
		{
			this.oid = null;
			this.attribute = attribute;
		}

		public static AttrOrOID getInstance(object obj)
		{
			if (obj is AttrOrOID)
			{
				return (AttrOrOID)obj;
			}

			if (obj != null)
			{
				if (obj is ASN1Encodable)
				{
					ASN1Encodable asn1Prim = ((ASN1Encodable)obj).toASN1Primitive();

					if (asn1Prim is ASN1ObjectIdentifier)
					{
						return new AttrOrOID(ASN1ObjectIdentifier.getInstance(asn1Prim));
					}
					if (asn1Prim is ASN1Sequence)
					{
						return new AttrOrOID(Attribute.getInstance(asn1Prim));
					}
				}
				if (obj is byte[])
				{
					try
					{
						return getInstance(ASN1Primitive.fromByteArray((byte[])obj));
					}
					catch (IOException)
					{
						throw new IllegalArgumentException("unknown encoding in getInstance()");
					}
				}
				throw new IllegalArgumentException("unknown object in getInstance(): " + obj.GetType().getName());
			}

			return null;
		}

		public virtual bool isOid()
		{
			return oid != null;
		}

		public virtual ASN1ObjectIdentifier getOid()
		{
			return oid;
		}

		public virtual Attribute getAttribute()
		{
			return attribute;
		}
		public override ASN1Primitive toASN1Primitive()
		{
			if (oid != null)
			{
				return oid;
			}

			return attribute.toASN1Primitive();
		}
	}

}