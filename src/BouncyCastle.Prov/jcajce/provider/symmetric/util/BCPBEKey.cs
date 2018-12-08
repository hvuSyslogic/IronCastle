namespace org.bouncycastle.jcajce.provider.symmetric.util
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using PBEParametersGenerator = org.bouncycastle.crypto.PBEParametersGenerator;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;

	public class BCPBEKey : PBEKey
	{
		internal string algorithm;
		internal ASN1ObjectIdentifier oid;
		internal int type;
		internal int digest;
		internal int keySize;
		internal int ivSize;
		internal CipherParameters param;
		internal PBEKeySpec pbeKeySpec;
		internal bool tryWrong = false;

		/// <param name="param"> </param>
		public BCPBEKey(string algorithm, ASN1ObjectIdentifier oid, int type, int digest, int keySize, int ivSize, PBEKeySpec pbeKeySpec, CipherParameters param)
		{
			this.algorithm = algorithm;
			this.oid = oid;
			this.type = type;
			this.digest = digest;
			this.keySize = keySize;
			this.ivSize = ivSize;
			this.pbeKeySpec = pbeKeySpec;
			this.param = param;
		}

		public BCPBEKey(string algName, KeySpec pbeSpec, CipherParameters param)
		{
			this.algorithm = algName;
			this.param = param;
		}

		public virtual string getAlgorithm()
		{
			return algorithm;
		}

		public virtual string getFormat()
		{
			return "RAW";
		}

		public virtual byte[] getEncoded()
		{
			if (param != null)
			{
				KeyParameter kParam;

				if (param is ParametersWithIV)
				{
					kParam = (KeyParameter)((ParametersWithIV)param).getParameters();
				}
				else
				{
					kParam = (KeyParameter)param;
				}

				return kParam.getKey();
			}
			else
			{
				if (type == PBE_Fields.PKCS12)
				{
					return PBEParametersGenerator.PKCS12PasswordToBytes(pbeKeySpec.getPassword());
				}
				else if (type == PBE_Fields.PKCS5S2_UTF8)
				{
					return PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(pbeKeySpec.getPassword());
				}
				else
				{
					return PBEParametersGenerator.PKCS5PasswordToBytes(pbeKeySpec.getPassword());
				}
			}
		}

		public virtual int getType()
		{
			return type;
		}

		public virtual int getDigest()
		{
			return digest;
		}

		public virtual int getKeySize()
		{
			return keySize;
		}

		public virtual int getIvSize()
		{
			return ivSize;
		}

		public virtual CipherParameters getParam()
		{
			return param;
		}

		/* (non-Javadoc)
		 * @see javax.crypto.interfaces.PBEKey#getPassword()
		 */
		public virtual char[] getPassword()
		{
			return pbeKeySpec.getPassword();
		}

		/* (non-Javadoc)
		 * @see javax.crypto.interfaces.PBEKey#getSalt()
		 */
		public virtual byte[] getSalt()
		{
			return pbeKeySpec.getSalt();
		}

		/* (non-Javadoc)
		 * @see javax.crypto.interfaces.PBEKey#getIterationCount()
		 */
		public virtual int getIterationCount()
		{
			return pbeKeySpec.getIterationCount();
		}

		public virtual ASN1ObjectIdentifier getOID()
		{
			return oid;
		}

		public virtual void setTryWrongPKCS12Zero(bool tryWrong)
		{
			this.tryWrong = tryWrong;
		}

		public virtual bool shouldTryWrongPKCS12()
		{
			return tryWrong;
		}
	}

}