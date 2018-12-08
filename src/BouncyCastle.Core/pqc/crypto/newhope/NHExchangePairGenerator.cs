﻿using BouncyCastle.Core.Port;

namespace org.bouncycastle.pqc.crypto.newhope
{

	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;

	public class NHExchangePairGenerator : ExchangePairGenerator
	{
		private readonly SecureRandom random;

		public NHExchangePairGenerator(SecureRandom random)
		{
			this.random = random;
		}

		public virtual ExchangePair GenerateExchange(AsymmetricKeyParameter senderPublicKey)
		{
			return generateExchange(senderPublicKey);
		}

		public virtual ExchangePair generateExchange(AsymmetricKeyParameter senderPublicKey)
		{
			NHPublicKeyParameters pubKey = (NHPublicKeyParameters)senderPublicKey;

			byte[] sharedValue = new byte[NewHope.AGREEMENT_SIZE];
			byte[] publicKeyValue = new byte[NewHope.SENDB_BYTES];

			NewHope.sharedB(random, sharedValue, publicKeyValue, pubKey.pubData);

			return new ExchangePair(new NHPublicKeyParameters(publicKeyValue), sharedValue);
		}
	}

}