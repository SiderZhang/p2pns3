/*
 *	Copyright © 2012,2013 Naim A.
 *
 *	This file is part of UDPT.
 *
 *		UDPT is free software: you can redistribute it and/or modify
 *		it under the terms of the GNU General Public License as published by
 *		the Free Software Foundation, either version 3 of the License, or
 *		(at your option) any later version.
 *
 *		UDPT is distributed in the hope that it will be useful,
 *		but WITHOUT ANY WARRANTY; without even the implied warranty of
 *		MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *		GNU General Public License for more details.
 *
 *		You should have received a copy of the GNU General Public License
 *		along with UDPT.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LOGGING_H_
#define LOGGING_H_

#include "udptSettings.hpp"
#include <string>
#include <iostream>
#include <queue>
#include <time.h>

namespace UDPT {
	using namespace std;
	class Logger {

	public:
		enum LogLevel {
			LL_ERROR 	= 0,
			LL_WARNING 	= 1,
			LL_INFO		= 2,
			LL_DEBUG	= 3
		};

		Logger (Settings *s);

		Logger (Settings *s, ostream &os);

		virtual ~Logger ();

		void log (enum LogLevel, string msg);
	private:
		ostream *logfile;
		enum LogLevel loglevel;
		bool closeStreamOnDestroy;

		static void setStream (Logger *logger, ostream &s);
	};
};

#endif /* LOGGING_H_ */
