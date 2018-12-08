using System;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x9
{


	/// <summary>
	/// The Parameters ASN.1 CHOICE from X9.62.
	/// </summary>
	public class X962Parameters : ASN1Object, ASN1Choice
	{
		private ASN1Primitive @params = null;

		public static X962Parameters getInstance(object obj)
		{
			if (obj == null || obj is X962Parameters)
			{
				return (X962Parameters)obj;
			}

			if (obj is ASN1Primitive)
			{
				return new X962Parameters((ASN1Primitive)obj);
			}

			if (obj is byte[])
			{
				try
				{
					return new X962Parameters(ASN1Primitive.fromByteArray((byte[])obj));
				}
				catch (Exception e)
				{
					throw new IllegalArgumentException("unable to parse encoded data: " + e.Message);
				}
			}

			throw new IllegalArgumentException("unknown object in getInstance()");
		}

		public static X962Parameters getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(obj.getObject()); // must be explicitly tagged
		}

		public X962Parameters(X9ECParameters ecParameters)
		{
			this.@params = ecParameters.toASN1Primitive();
		}

		public X962Parameters(ASN1ObjectIdentifier namedCurve)
		{
			this.@params = namedCurve;
		}

		public X962Parameters(ASN1Null obj)
		{
			this.@params = obj;
		}

		/// @deprecated use getInstance() 
		public X962Parameters(ASN1Primitive obj)
		{
			this.@params = obj;
		}

		public virtual bool isNamedCurve()
		{
			return (@params is ASN1ObjectIdentifier);
		}

		public virtual bool isImplicitlyCA()
		{
			return (@params is ASN1Null);
		}

		public virtual ASN1Primitive getParameters()
		{
			return @params;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		/// Parameters ::= CHOICE {
		///    ecParameters ECParameters,
		///    namedCurve   CURVES.&amp;id({CurveNames}),
		///    implicitlyCA NULL
		/// }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			return @params;
		}
	}

}