﻿using System;

namespace org.bouncycastle.dvcs
{
	/// <summary>
	/// Exception thrown when failed to initialize some DVCS-related staff.
	/// </summary>
	public class DVCSConstructionException : DVCSException
	{
		private const long serialVersionUID = 660035299653583980L;

		public DVCSConstructionException(string message) : base(message)
		{
		}

		public DVCSConstructionException(string message, Exception cause) : base(message, cause)
		{
		}
	}

}