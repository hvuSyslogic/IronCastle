﻿using System.IO;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// A basic parser for a SEQUENCE object
	/// </summary>
	public interface ASN1SequenceParser : ASN1Encodable, InMemoryRepresentable
	{
		/// <summary>
		/// Read the next object from the underlying object representing a SEQUENCE.
		/// </summary>
		/// <exception cref="IOException"> for bad input stream. </exception>
		/// <returns> the next object, null if we are at the end. </returns>
		ASN1Encodable readObject();
	}

}