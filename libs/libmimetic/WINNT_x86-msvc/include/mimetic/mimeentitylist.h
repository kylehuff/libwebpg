/***************************************************************************
    copyright            : (C) 2002-2008 by Stefano Barbato
    email                : stefano@codesink.org

    $Id: mimeentitylist.h,v 1.8 2008-10-07 11:06:25 tat Exp $
 ***************************************************************************/
#ifndef _MIMETIC_MIME_ENTITY_LIST_
#define _MIMETIC_MIME_ENTITY_LIST_
// The below is to overcome an issue with using std::list in windows.
//  the solution is to use std::vector
#include <vector>
#include <string>

namespace mimetic
{

class MimeEntity;

/// List of MimeEntity classes
typedef std::vector<MimeEntity*> MimeEntityList;


}

#endif
