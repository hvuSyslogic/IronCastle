using System;
using org.bouncycastle.Port;

namespace org.bouncycastle.util
{
	/// <summary>
	/// Utility methods for processing String objects containing IP addresses.
	/// </summary>
	public class IPAddress
	{
		/// <summary>
		/// Validate the given IPv4 or IPv6 address.
		/// </summary>
		/// <param name="address"> the IP address as a String.
		/// </param>
		/// <returns> true if a valid address, false otherwise </returns>
		public static bool isValid(string address)
		{
			return isValidIPv4(address) || isValidIPv6(address);
		}

		/// <summary>
		/// Validate the given IPv4 or IPv6 address and netmask.
		/// </summary>
		/// <param name="address"> the IP address as a String.
		/// </param>
		/// <returns> true if a valid address with netmask, false otherwise </returns>
		public static bool isValidWithNetMask(string address)
		{
			return isValidIPv4WithNetmask(address) || isValidIPv6WithNetmask(address);
		}

		/// <summary>
		/// Validate the given IPv4 address.
		/// </summary>
		/// <param name="address"> the IP address as a String.
		/// </param>
		/// <returns> true if a valid IPv4 address, false otherwise </returns>
		public static bool isValidIPv4(string address)
		{
			if (address.Length == 0)
			{
				return false;
			}

			int octet;
			int octets = 0;

			string temp = address + ".";

			int pos;
			int start = 0;
			while (start < temp.Length && (pos = temp.IndexOf('.', start)) > start)
			{
				if (octets == 4)
				{
					return false;
				}
				try
				{
					octet = int.Parse(temp.Substring(start, pos - start));
				}
				catch (NumberFormatException)
				{
					return false;
				}
				if (octet < 0 || octet > 255)
				{
					return false;
				}
				start = pos + 1;
				octets++;
			}

			return octets == 4;
		}

		public static bool isValidIPv4WithNetmask(string address)
		{
			int index = address.IndexOf("/", StringComparison.Ordinal);
			string mask = address.Substring(index + 1);

			return (index > 0) && isValidIPv4(address.Substring(0, index)) && (isValidIPv4(mask) || isMaskValue(mask, 32));
		}

		public static bool isValidIPv6WithNetmask(string address)
		{
			int index = address.IndexOf("/", StringComparison.Ordinal);
			string mask = address.Substring(index + 1);

			return (index > 0) && (isValidIPv6(address.Substring(0, index)) && (isValidIPv6(mask) || isMaskValue(mask, 128)));
		}

		private static bool isMaskValue(string component, int size)
		{
			try
			{
				int value = int.Parse(component);

				return value >= 0 && value <= size;
			}
			catch (NumberFormatException)
			{
				return false;
			}
		}

		/// <summary>
		/// Validate the given IPv6 address.
		/// </summary>
		/// <param name="address"> the IP address as a String.
		/// </param>
		/// <returns> true if a valid IPv4 address, false otherwise </returns>
		public static bool isValidIPv6(string address)
		{
			if (address.Length == 0)
			{
				return false;
			}

			int octet;
			int octets = 0;

			string temp = address + ":";
			bool doubleColonFound = false;
			int pos;
			int start = 0;
			while (start < temp.Length && (pos = temp.IndexOf(':', start)) >= start)
			{
				if (octets == 8)
				{
					return false;
				}

				if (start != pos)
				{
					string value = temp.Substring(start, pos - start);

					if (pos == (temp.Length - 1) && value.IndexOf('.') > 0)
					{
						if (!isValidIPv4(value))
						{
							return false;
						}

						octets++; // add an extra one as address covers 2 words.
					}
					else
					{
						try
						{
							octet = Convert.ToInt32(temp.Substring(start, pos - start), 16);
						}
						catch (NumberFormatException)
						{
							return false;
						}
						if (octet < 0 || octet > 0xffff)
						{
							return false;
						}
					}
				}
				else
				{
					if (pos != 1 && pos != temp.Length - 1 && doubleColonFound)
					{
						return false;
					}
					doubleColonFound = true;
				}
				start = pos + 1;
				octets++;
			}

			return octets == 8 || doubleColonFound;
		}
	}



}