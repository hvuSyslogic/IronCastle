using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509.qualified
{

	/// <summary>
	/// The TypeOfBiometricData object.
	/// <pre>
	/// TypeOfBiometricData ::= CHOICE {
	///   predefinedBiometricType   PredefinedBiometricType,
	///   biometricDataOid          OBJECT IDENTIFIER }
	/// 
	/// PredefinedBiometricType ::= INTEGER {
	///   picture(0),handwritten-signature(1)}
	///   (picture|handwritten-signature)
	/// </pre>
	/// </summary>
	public class TypeOfBiometricData : ASN1Object, ASN1Choice
	{
		public const int PICTURE = 0;
		public const int HANDWRITTEN_SIGNATURE = 1;

		internal ASN1Encodable obj;

		public static TypeOfBiometricData getInstance(object obj)
		{
			if (obj == null || obj is TypeOfBiometricData)
			{
				return (TypeOfBiometricData)obj;
			}

			if (obj is ASN1Integer)
			{
				ASN1Integer predefinedBiometricTypeObj = ASN1Integer.getInstance(obj);
				int predefinedBiometricType = predefinedBiometricTypeObj.getValue().intValue();

				return new TypeOfBiometricData(predefinedBiometricType);
			}
			else if (obj is ASN1ObjectIdentifier)
			{
				ASN1ObjectIdentifier BiometricDataID = ASN1ObjectIdentifier.getInstance(obj);
				return new TypeOfBiometricData(BiometricDataID);
			}

			throw new IllegalArgumentException("unknown object in getInstance");
		}

		public TypeOfBiometricData(int predefinedBiometricType)
		{
			if (predefinedBiometricType == PICTURE || predefinedBiometricType == HANDWRITTEN_SIGNATURE)
			{
					obj = new ASN1Integer(predefinedBiometricType);
			}
			else
			{
				throw new IllegalArgumentException("unknow PredefinedBiometricType : " + predefinedBiometricType);
			}
		}

		public TypeOfBiometricData(ASN1ObjectIdentifier BiometricDataID)
		{
			obj = BiometricDataID;
		}

		public virtual bool isPredefined()
		{
			return obj is ASN1Integer;
		}

		public virtual int getPredefinedBiometricType()
		{
			return ((ASN1Integer)obj).getValue().intValue();
		}

		public virtual ASN1ObjectIdentifier getBiometricDataOid()
		{
			return (ASN1ObjectIdentifier)obj;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return obj.toASN1Primitive();
		}
	}

}