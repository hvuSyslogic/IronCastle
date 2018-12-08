using System;

namespace org.bouncycastle.jcajce.provider.symmetric.util
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;

	public class BaseSecretKeyFactory : SecretKeyFactorySpi, PBE
	{
		protected internal string algName;
		protected internal ASN1ObjectIdentifier algOid;

		public BaseSecretKeyFactory(string algName, ASN1ObjectIdentifier algOid)
		{
			this.algName = algName;
			this.algOid = algOid;
		}

		public override SecretKey engineGenerateSecret(KeySpec keySpec)
		{
			if (keySpec is SecretKeySpec)
			{
				return new SecretKeySpec(((SecretKeySpec)keySpec).getEncoded(), algName);
			}

			throw new InvalidKeySpecException("Invalid KeySpec");
		}

		public override KeySpec engineGetKeySpec(SecretKey key, Class keySpec)
		{
			if (keySpec == null)
			{
				throw new InvalidKeySpecException("keySpec parameter is null");
			}
			if (key == null)
			{
				throw new InvalidKeySpecException("key parameter is null");
			}

			if (typeof(SecretKeySpec).isAssignableFrom(keySpec))
			{
				return new SecretKeySpec(key.getEncoded(), algName);
			}

			try
			{
				Class[] parameters = new Class[] {typeof(byte[])};

				Constructor c = keySpec.getConstructor(parameters);
				object[] p = new object[1];

				p[0] = key.getEncoded();

				return (KeySpec)c.newInstance(p);
			}
			catch (Exception e)
			{
				throw new InvalidKeySpecException(e.ToString());
			}
		}

		public override SecretKey engineTranslateKey(SecretKey key)
		{
			if (key == null)
			{
				throw new InvalidKeyException("key parameter is null");
			}

			if (!key.getAlgorithm().equalsIgnoreCase(algName))
			{
				throw new InvalidKeyException("Key not of type " + algName + ".");
			}

			return new SecretKeySpec(key.getEncoded(), algName);
		}
	}

}