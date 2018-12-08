using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{

	public class AttCertIssuer : ASN1Object, ASN1Choice
	{
		internal ASN1Encodable obj;
		internal ASN1Primitive choiceObj;

		public static AttCertIssuer getInstance(object obj)
		{
			if (obj == null || obj is AttCertIssuer)
			{
				return (AttCertIssuer)obj;
			}
			else if (obj is V2Form)
			{
				return new AttCertIssuer(V2Form.getInstance(obj));
			}
			else if (obj is GeneralNames)
			{
				return new AttCertIssuer((GeneralNames)obj);
			}
			else if (obj is ASN1TaggedObject)
			{
				return new AttCertIssuer(V2Form.getInstance((ASN1TaggedObject)obj, false));
			}
			else if (obj is ASN1Sequence)
			{
				return new AttCertIssuer(GeneralNames.getInstance(obj));
			}

			throw new IllegalArgumentException("unknown object in factory: " + obj.GetType().getName());
		}

		public static AttCertIssuer getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(obj.getObject()); // must be explicitly tagged
		}

		/// <summary>
		/// Don't use this one if you are trying to be RFC 3281 compliant.
		/// Use it for v1 attribute certificates only.
		/// </summary>
		/// <param name="names"> our GeneralNames structure </param>
		public AttCertIssuer(GeneralNames names)
		{
			obj = names;
			choiceObj = obj.toASN1Primitive();
		}

		public AttCertIssuer(V2Form v2Form)
		{
			obj = v2Form;
			choiceObj = new DERTaggedObject(false, 0, obj);
		}

		public virtual ASN1Encodable getIssuer()
		{
			return obj;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		///  AttCertIssuer ::= CHOICE {
		///       v1Form   GeneralNames,  -- MUST NOT be used in this
		///                               -- profile
		///       v2Form   [0] V2Form     -- v2 only
		///  }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			return choiceObj;
		}
	}

}