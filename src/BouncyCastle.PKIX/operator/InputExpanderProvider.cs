﻿namespace org.bouncycastle.@operator
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public interface InputExpanderProvider
	{
		InputExpander get(AlgorithmIdentifier algorithm);
	}

}