using System.IO;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{


	/// <summary>
	/// <pre>
	/// BodyPartReference ::= CHOICE {
	///    bodyPartID           BodyPartID,
	///    bodyPartPath         BodyPartPath
	/// }
	/// </pre>
	/// </summary>
	public class BodyPartReference : ASN1Object, ASN1Choice
	{
		private readonly BodyPartID bodyPartID;
		private readonly BodyPartPath bodyPartPath;

		public BodyPartReference(BodyPartID bodyPartID)
		{
			this.bodyPartID = bodyPartID;
			this.bodyPartPath = null;
		}

		public BodyPartReference(BodyPartPath bodyPartPath)
		{
			this.bodyPartID = null;
			this.bodyPartPath = bodyPartPath;
		}

		public static BodyPartReference getInstance(object obj)
		{
			if (obj is BodyPartReference)
			{
				return (BodyPartReference)obj;
			}

			if (obj != null)
			{
				if (obj is ASN1Encodable)
				{
					ASN1Encodable asn1Prim = ((ASN1Encodable)obj).toASN1Primitive();

					if (asn1Prim is ASN1Integer)
					{
						return new BodyPartReference(BodyPartID.getInstance(asn1Prim));
					}
					if (asn1Prim is ASN1Sequence)
					{
						return new BodyPartReference(BodyPartPath.getInstance(asn1Prim));
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

		public virtual bool isBodyPartID()
		{
			return bodyPartID != null;
		}

		public virtual BodyPartID getBodyPartID()
		{
			return bodyPartID;
		}

		public virtual BodyPartPath getBodyPartPath()
		{
			return bodyPartPath;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			if (bodyPartID != null)
			{
				return bodyPartID.toASN1Primitive();
			}
			else
			{
				return bodyPartPath.toASN1Primitive();
			}
		}
	}

}