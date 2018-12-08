using System;

namespace org.bouncycastle.openssl
{

	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;

	public class PEMEncryptedKeyPair
	{
		private readonly string dekAlgName;
		private readonly byte[] iv;
		private readonly byte[] keyBytes;
		private readonly PEMKeyPairParser parser;

		public PEMEncryptedKeyPair(string dekAlgName, byte[] iv, byte[] keyBytes, PEMKeyPairParser parser)
		{
			this.dekAlgName = dekAlgName;
			this.iv = iv;
			this.keyBytes = keyBytes;
			this.parser = parser;
		}

		public virtual PEMKeyPair decryptKeyPair(PEMDecryptorProvider keyDecryptorProvider)
		{
			try
			{
				PEMDecryptor keyDecryptor = keyDecryptorProvider.get(dekAlgName);

				return parser.parse(keyDecryptor.decrypt(keyBytes, iv));
			}
			catch (IOException e)
			{
				throw e;
			}
			catch (OperatorCreationException e)
			{
				throw new PEMException("cannot create extraction operator: " + e.Message, e);
			}
			catch (Exception e)
			{
				throw new PEMException("exception processing key pair: " + e.Message, e);
			}
		}
	}

}