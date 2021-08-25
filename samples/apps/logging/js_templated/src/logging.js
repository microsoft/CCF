function get_id_from_request_query(request) {
  const elements = request.query.split("&");
  for (const kv of elements) {
    const [k, v] = kv.split("=");
    if (k == "id") {
      return ccf.strToBuf(v);
    }
  }
  throw new Error("Could not find 'id' in query");
}

function get_record(map, id) {
  const msg = map.get(id);
  if (msg === undefined) {
    return { body: { error: "No such key" } };
  }
  return { body: { msg: ccf.bufToStr(msg) } };
}

export function get_private(request) {
  const id = get_id_from_request_query(request);
  return get_record(ccf.kv["records"], id);
}

export function post_private(request) {
  let params = request.body.json();
  ccf.kv["records"].set(
    ccf.strToBuf(params.id.toString()),
    ccf.strToBuf(params.msg)
  );
  return { body: true };
}

export function get_private_at(request) {
  const id = ccf.strToBuf(request.params.id);
  return get_record(ccf.kv["records"], id);
}

export function post_private_at(request) {
  let params = request.body.json();
  ccf.kv["records"].set(
    ccf.strToBuf(request.params.id),
    ccf.strToBuf(params.msg)
  );
  return { body: true };
}

export function nop(request) {
  return { body: true };
}

// To make things worse, this module is extremely large, so slow to deserialise
let s = `Lorem ipsum dolor sit amet, consectetur adipiscing elit. In id nibh arcu. Vivamus maximus pretium sapien, id tincidunt leo consectetur a. Vestibulum nibh ante, tincidunt non dolor vel, placerat gravida ex. Pellentesque non cursus lacus. In efficitur nunc sit amet ligula efficitur tincidunt. Etiam id lobortis sapien. Nam pretium maximus nulla. In consectetur urna massa, sed bibendum sapien posuere vel. Nunc ullamcorper risus et arcu pretium, non auctor mi aliquam. Aliquam erat volutpat. Nullam sollicitudin condimentum nulla, vitae efficitur risus finibus ac. Fusce tempor maximus lacus. Sed vulputate at odio vitae ullamcorper. Nunc vitae augue cursus, condimentum enim vitae, blandit nunc. Integer sed odio at nibh tempor mattis at consectetur massa.

Aliquam vestibulum, elit vel egestas molestie, orci ex ultricies leo, non eleifend dui magna at turpis. Curabitur dictum blandit ex, congue lobortis nisl euismod in. Pellentesque pellentesque cursus eros sed condimentum. Proin vehicula urna nec tortor lobortis varius. Donec sit amet dignissim leo. Nullam pretium fringilla nisi nec vestibulum. Sed vehicula, purus sed dapibus efficitur, sem nulla imperdiet sem, eu scelerisque orci neque id lectus. Ut at dui placerat, luctus est vel, lacinia sem.

Maecenas fringilla sem ligula, eget dignissim metus ullamcorper sit amet. Phasellus a eros dui. Sed congue finibus porttitor. Sed felis ante, luctus non nibh vel, dapibus fermentum ipsum. Sed sed eros augue. Suspendisse potenti. Donec gravida massa vel viverra mattis.

Etiam venenatis sit amet enim vitae imperdiet. In fermentum urna non sem congue, vel iaculis tellus tempus. Proin semper accumsan venenatis. Integer interdum tempus tempus. Maecenas fringilla scelerisque ante sit amet interdum. In porttitor bibendum pulvinar. Sed consectetur nisi faucibus leo fermentum molestie. Aenean sagittis pharetra ligula. Donec sodales justo nisl, eu porta tortor volutpat ut. Praesent dolor arcu, hendrerit non auctor in, blandit quis tellus. Nam maximus purus quis elit hendrerit auctor. Donec in erat lacinia, finibus ipsum ac, porttitor libero. Fusce pretium nunc ut ex posuere, a interdum massa vehicula. Aliquam eu lobortis lacus. Mauris ac turpis at turpis tincidunt dapibus.

Phasellus at laoreet nibh, at ornare est. Donec placerat, purus vitae dapibus accumsan, diam nisl volutpat lorem, vel ultrices augue metus ut nunc. Vivamus vulputate mollis diam, a maximus nunc fermentum et. Etiam non posuere metus, eget porta leo. Phasellus cursus leo quis risus aliquam accumsan. Donec tempus lorem id ligula dapibus convallis. Etiam eget felis sit amet justo suscipit mollis sit amet egestas turpis. Phasellus facilisis enim eget congue semper. Aenean sodales sed erat ut accumsan. Donec eget scelerisque odio, ut maximus dolor. Donec ante arcu, cursus nec vestibulum non, dapibus sed nisl. Aenean a scelerisque arcu. Donec ultrices enim at enim elementum bibendum. Praesent ac augue dolor. Etiam quis turpis quis ligula posuere scelerisque et accumsan odio. Aliquam lacinia ornare elit, sagittis condimentum lacus congue vel.

Donec felis nisi, convallis elementum vulputate sit amet, tempus sed felis. Aenean fermentum iaculis sodales. Donec sed nibh egestas, finibus nisl in, auctor sapien. Sed at mollis enim. Donec eu tellus luctus, gravida erat non, fringilla velit. Pellentesque euismod hendrerit lacus non mollis. Integer at nulla id dolor elementum rutrum vitae vel neque.

Nunc sed mauris porttitor, interdum libero nec, molestie risus. Vivamus cursus, magna ut faucibus congue, nisi augue facilisis odio, a aliquam purus ipsum bibendum purus. Praesent sit amet libero magna. Aliquam sit amet aliquam lectus. Fusce euismod condimentum mauris, quis vestibulum est ullamcorper vel. Phasellus turpis est, faucibus sit amet tincidunt eu, faucibus nec massa. Nulla vulputate lacus nec ipsum dictum, fringilla varius mauris ultrices. Nulla bibendum molestie bibendum. Vestibulum turpis urna, pulvinar eu leo sit amet, laoreet ultrices tortor. Fusce a urna nisl. Duis porta justo a felis ullamcorper vehicula. Integer nec velit malesuada enim venenatis tempor non ac leo. Phasellus eu posuere ipsum, pharetra varius metus. Ut eu efficitur orci. Curabitur sed mollis metus, maximus pharetra metus. Nullam sodales maximus risus eu facilisis.

Nam varius lobortis turpis vitae tempus. Fusce diam lorem, maximus non commodo eu, iaculis quis dolor. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Nulla non dapibus turpis, vitae feugiat velit. Vivamus convallis purus accumsan arcu tincidunt, vel luctus lorem lobortis. Nunc pharetra cursus dolor vitae vestibulum. Cras sodales accumsan luctus. Aliquam ullamcorper ligula dictum, dignissim elit at, scelerisque orci. Morbi rhoncus gravida mattis. Pellentesque nec tristique justo. Morbi at facilisis sapien, vitae finibus tellus. Ut a lacinia diam. Aliquam tincidunt lorem eu ipsum ullamcorper, sed laoreet lectus blandit.

Praesent eu tristique ex. Praesent ac ultrices magna. Cras faucibus gravida ipsum sed suscipit. Curabitur bibendum neque at ultrices lacinia. Nunc facilisis lorem egestas quam maximus, id ornare nulla fermentum. Donec a est aliquet, mattis erat sit amet, imperdiet leo. Donec in lorem cursus, interdum elit at, porta sem. Aenean sit amet nunc in justo rhoncus eleifend.

Etiam aliquet ipsum eget neque sollicitudin, in molestie risus ultricies. Proin purus neque, cursus at arcu sed, imperdiet malesuada ligula. Suspendisse laoreet ac purus vel feugiat. Aliquam malesuada fermentum volutpat. Curabitur in magna sit amet nulla vulputate luctus cursus nec neque. Interdum et malesuada fames ac ante ipsum primis in faucibus. Sed purus ex, semper at ultricies id, ultricies quis lacus. Proin commodo venenatis nunc nec tempus. Vivamus sit amet dolor vulputate, placerat velit quis, condimentum turpis. Duis at turpis est.

Lorem ipsum dolor sit amet, consectetur adipiscing elit. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Nullam magna sem, scelerisque non quam in, ultricies porta diam. Duis at tristique quam, sed convallis nisl. Nulla porta, orci sed interdum dictum, dui orci pretium erat, non lacinia ex nisi feugiat nisi. Morbi et tincidunt magna. Curabitur vel massa vitae ligula dignissim venenatis non nec dui.

Maecenas tincidunt ullamcorper posuere. Maecenas euismod, nisi vitae gravida rhoncus, sapien nisl porttitor massa, at gravida magna leo at mi. Aenean condimentum aliquet mollis. Phasellus malesuada egestas arcu, vel finibus sapien maximus dictum. Suspendisse molestie eros a tortor ullamcorper finibus. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Curabitur cursus sapien non libero pretium, ac pulvinar mauris congue. Aliquam congue orci sit amet pulvinar accumsan. Aliquam in tristique erat. Aenean a porttitor lacus. Donec placerat tempus ante, quis ullamcorper lectus rhoncus nec. Nunc feugiat erat quis odio ultricies, nec rutrum neque rhoncus. Nullam ligula nulla, blandit at mi sit amet, pretium cursus sapien. Phasellus varius accumsan aliquet. In ornare molestie mauris at tincidunt.

Vestibulum vel turpis aliquet, vestibulum odio non, pretium magna. Curabitur volutpat, massa facilisis suscipit consequat, augue erat porttitor ex, non sodales ipsum elit ac nibh. Aliquam sodales magna in tortor congue, nec pretium ligula euismod. In hac habitasse platea dictumst. Fusce interdum ipsum a nulla interdum facilisis. Suspendisse finibus augue eu elit efficitur sollicitudin. Etiam dignissim tempus varius. Quisque bibendum finibus ex, vitae faucibus orci ultricies vitae.

Duis augue eros, ultrices ut dignissim sit amet, sollicitudin a nulla. Nulla ornare dignissim mauris at maximus. Proin placerat magna facilisis tortor pretium, sit amet luctus mi aliquam. Sed id suscipit leo, quis lobortis orci. Maecenas sodales nibh id velit tempus, sed sagittis justo tempus. Sed sodales, mauris a laoreet lobortis, tellus purus lobortis dolor, in pellentesque enim justo in nunc. Vestibulum vulputate eros quis eleifend tincidunt. Aliquam tristique, metus eu bibendum luctus, libero lacus facilisis urna, sit amet mollis enim tellus at tellus. Mauris vitae accumsan dolor, a maximus lectus. Mauris pretium arcu orci, at mollis tellus lobortis ac. Nunc scelerisque vestibulum metus ac consectetur. Maecenas nec leo consectetur, tempor odio vel, gravida lectus.

Donec elementum risus nulla, vel feugiat tortor imperdiet in. Fusce pulvinar neque quis sem accumsan vestibulum. Nullam vitae ante at massa efficitur auctor feugiat quis arcu. Phasellus et luctus erat, ac condimentum turpis. Maecenas condimentum ante erat, vel tempus urna ornare nec. Fusce eu augue scelerisque, commodo mi at, feugiat mauris. Pellentesque accumsan risus pellentesque ullamcorper egestas. Duis congue pharetra nisi id iaculis. Praesent et pulvinar lorem, vitae fringilla turpis. Vestibulum pulvinar eros efficitur mauris finibus ultrices. Praesent tempus ligula sed risus mattis, eget bibendum ante gravida. Nulla nulla sem, mollis sed ligula in, molestie sodales urna.

Pellentesque sollicitudin, lorem at fermentum porta, nulla tellus vestibulum est, sit amet vehicula purus urna consectetur risus. Nullam eget ullamcorper nunc, in accumsan mauris. Fusce hendrerit enim et tempor tristique. Suspendisse id ligula non lacus laoreet iaculis. Nunc ac erat enim. Mauris quis elementum metus. Nullam tristique, erat et porta varius, lorem sem aliquet tortor, non interdum odio sem mattis libero. Maecenas venenatis arcu sed magna feugiat ullamcorper. Donec venenatis justo at est gravida, sit amet hendrerit leo bibendum. Proin vestibulum quam sed urna semper, at dapibus sem posuere. Duis eget posuere massa. Aliquam vel felis ac est tristique feugiat. Praesent ac dapibus sem, id porta est.

Nunc mi sapien, consequat eu commodo ut, efficitur eu ante. Nam congue lorem et augue auctor, sit amet tempor nulla aliquet. In auctor ipsum dolor, quis volutpat justo tincidunt eget. Nulla egestas venenatis mollis. Nullam scelerisque, dui in iaculis interdum, dolor quam varius odio, fringilla porttitor arcu sapien ac eros. Nunc tempor ex sed eros pellentesque, eget euismod felis ornare. Fusce vitae pellentesque mi. Aliquam bibendum lobortis enim, quis tempor nisl tempus et. Nulla condimentum luctus tempus. Suspendisse vulputate quam quis placerat varius. Sed ornare dapibus velit in iaculis. Sed accumsan est felis, ac pretium nibh commodo quis. Vestibulum ultrices sapien sed elit tincidunt sagittis. Quisque quis metus eu ligula molestie aliquet nec vel nisl. Fusce nunc enim, porttitor et posuere pulvinar, placerat et mauris.

Sed id lectus eget metus commodo pulvinar ac sit amet mauris. Suspendisse tempor eleifend elementum. Sed molestie porta erat, non venenatis ex fermentum a. Mauris volutpat, mauris at pharetra maximus, urna velit placerat nisi, sit amet ultricies neque eros vitae magna. Praesent leo ipsum, iaculis sit amet ante nec, tempor tempus nisl. Quisque placerat accumsan sodales. Sed ac dictum risus, eu rutrum sapien. Nulla sed sem eget mauris placerat pretium vitae in odio. Pellentesque urna ex, eleifend vitae convallis bibendum, elementum sit amet turpis. Ut fringilla consectetur massa, ut dictum nibh pulvinar non. Phasellus vel odio neque. Nunc dictum facilisis tristique. Suspendisse fermentum eu nulla a tempus.

In hac habitasse platea dictumst. Pellentesque urna turpis, pharetra quis auctor ac, placerat maximus ipsum. Cras efficitur, ex eu sodales tempus, metus risus pellentesque tortor, vel ullamcorper diam nibh vitae mauris. Mauris sodales pharetra quam ut consectetur. Morbi ornare blandit purus molestie laoreet. Sed eget lacinia mi. Vivamus id ex sed nulla eleifend gravida. Nam in metus consectetur, luctus libero et, laoreet mi. Aliquam et felis id quam euismod lobortis id vel enim. Duis in justo metus. Praesent et pellentesque arcu. Ut sagittis fermentum tortor. Fusce interdum quam vitae metus interdum, nec bibendum nunc posuere.

Maecenas ac convallis justo, quis facilisis nibh. Fusce bibendum sed ante a commodo. Maecenas faucibus ex et neque varius, quis sollicitudin nulla dignissim. Aenean felis mauris, viverra vitae dictum sed, tempor nec justo. Praesent pharetra lobortis magna et tempor. Ut et euismod mauris, in maximus risus. Quisque ligula sem, molestie sed nunc ac, commodo tristique massa. Cras porttitor rutrum libero, ac pretium arcu luctus sed. Aenean nulla risus, maximus ut risus ac, pulvinar rhoncus nunc.

Donec sollicitudin lorem quis nisl varius iaculis. Pellentesque condimentum porttitor posuere. Nulla vel metus ex. Phasellus euismod dignissim mi, non tincidunt dolor molestie vel. Proin accumsan dui ut hendrerit pharetra. Integer augue turpis, volutpat interdum efficitur ornare, sodales rhoncus neque. Vestibulum feugiat sodales blandit. Aliquam scelerisque tristique leo, sit amet tristique ante congue mollis. Mauris vehicula ultricies velit, ac aliquam lorem ultrices ac. Curabitur quis faucibus ante, eu sodales metus. Fusce blandit tincidunt nibh non dignissim.

Sed purus mauris, accumsan blandit molestie eget, elementum ac nibh. Integer sollicitudin mi a metus placerat pulvinar. Fusce semper arcu eleifend nibh dictum, non porttitor tortor tincidunt. Donec eleifend purus nec ante semper, id tincidunt orci ullamcorper. Sed vehicula auctor rhoncus. Cras vel convallis purus, ac tempus risus. Pellentesque at metus laoreet est euismod dapibus. Nam faucibus ante fringilla ipsum sollicitudin, quis eleifend mi tincidunt. Donec bibendum nec quam sit amet lacinia. Proin dapibus elit nec mi pulvinar, et condimentum tellus tempor. Aenean fringilla augue condimentum lacus rhoncus posuere. Fusce porta in nulla in luctus. Praesent fringilla suscipit ante, id imperdiet nisi rhoncus a.

Nunc sit amet nisi a risus fringilla euismod vitae nec ex. Fusce a ligula accumsan, tempus felis quis, egestas mi. Duis sed elit sed arcu vehicula efficitur quis ut nibh. Nulla scelerisque elit in risus maximus, at rhoncus quam scelerisque. In porta magna sed tellus sodales, nec pretium dui varius. Nulla sodales nisi vitae magna consequat, id vehicula lectus pellentesque. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Integer tempor leo lectus, a consectetur metus maximus rhoncus. Nunc tincidunt faucibus erat in placerat.

Quisque at consectetur erat. Nulla bibendum nisl velit, non cursus est blandit vitae. Proin ac velit sed tortor lacinia consequat quis sit amet risus. Aenean euismod pharetra viverra. Sed et magna eget lacus euismod varius. Ut hendrerit diam sed vulputate dapibus. Fusce vitae lacus nec sem consectetur aliquam. Suspendisse mattis eros ac ipsum pharetra pellentesque. Praesent id eros at eros tincidunt aliquet. Mauris tellus felis, vehicula nec nulla id, elementum ornare neque. Sed feugiat efficitur fermentum. Cras eu auctor massa. Nulla ut sem non nunc fringilla pretium at id dui. Quisque quis tellus fringilla, vulputate neque a, finibus mi. Donec varius ultrices nibh eu maximus.

Proin non nisi sem. Pellentesque quis lectus eu mi maximus luctus a a arcu. Donec vitae rutrum massa, eget interdum lectus. Aenean rhoncus lobortis pellentesque. Proin malesuada purus eget tellus lacinia, quis suscipit orci sodales. Aenean erat urna, laoreet a mattis id, vulputate ac eros. Duis quis tortor non mauris maximus posuere. Nullam eget dui a dolor volutpat venenatis. Morbi porta sit amet est nec auctor. Suspendisse potenti. Phasellus et urna iaculis, varius mi sit amet, commodo quam. Nullam ut augue enim. Phasellus varius lacus sagittis dui mattis, vehicula rhoncus magna tristique.

Vivamus at nibh scelerisque, euismod nisl varius, blandit velit. Aliquam erat volutpat. Vestibulum lobortis lorem eu dolor lacinia, sed imperdiet sem lacinia. Sed sollicitudin est eget iaculis aliquet. Fusce est eros, condimentum molestie luctus vitae, imperdiet ac lorem. Aenean vel massa sapien. Praesent a nunc nec lorem consectetur varius porta ut odio. Sed vel blandit lectus. Pellentesque consequat vulputate lorem et fermentum. Etiam ut leo nisi. Vivamus in nulla quis dui condimentum hendrerit sed at dui. Aenean aliquam finibus tincidunt. Vivamus iaculis cursus magna, vel rutrum ipsum tempus ac. Interdum et malesuada fames ac ante ipsum primis in faucibus.

Mauris id dui faucibus, iaculis ante et, viverra felis. Vestibulum sed metus mattis, eleifend sem a, luctus ex. Curabitur molestie vitae metus in fermentum. Nunc porttitor in augue non interdum. Phasellus tempus justo metus, ornare lobortis nibh maximus eu. Vestibulum gravida non velit vitae sagittis. Ut ornare fermentum iaculis. Nam sit amet euismod mauris. Mauris pretium imperdiet ipsum, nec tincidunt nunc tincidunt eu.

Nulla facilisi. Phasellus nec dui ipsum. Proin iaculis bibendum velit, et aliquam ante placerat vitae. Aliquam tincidunt, mauris sit amet porta ultrices, nibh ex tincidunt lorem, quis cursus ipsum nisi id ipsum. Morbi condimentum sem quis neque laoreet, sed condimentum erat sodales. Donec vitae dolor posuere, facilisis elit ut, dapibus dui. Aliquam eros augue, euismod eget convallis quis, fringilla a nunc. Sed dignissim laoreet dolor. Nullam posuere, sapien euismod faucibus placerat, sapien tellus suscipit lacus, non fermentum lacus ex in nunc. Mauris id nunc aliquam, sagittis quam vel, ornare ante. Quisque ac malesuada ex, at sagittis nibh. Ut sed vulputate dolor. Sed dictum enim sed neque accumsan facilisis. Duis ac vehicula mi. Maecenas orci purus, elementum at felis ac, rutrum imperdiet urna. Nam scelerisque augue a condimentum sodales.

Suspendisse eu pellentesque leo, a bibendum urna. Vestibulum metus nibh, efficitur eu sodales a, pulvinar in tortor. Nullam euismod luctus massa, ac tincidunt velit ultrices non. Integer vitae faucibus elit, a vehicula enim. Donec facilisis quam ut ex commodo scelerisque. Nullam suscipit velit tellus, nec egestas libero tincidunt sed. Fusce vehicula est vel suscipit ullamcorper. Suspendisse non commodo nibh. Vestibulum in volutpat eros. Nunc venenatis id eros sed scelerisque.

Nullam a dolor dolor. Aenean lorem mauris, elementum sit amet neque id, luctus rhoncus risus. Morbi id tempor dolor. Sed sed nisi nunc. Sed mollis nulla eget felis ullamcorper bibendum. Curabitur scelerisque diam tellus, eget egestas eros placerat sit amet. Proin in elit ut metus molestie efficitur. Maecenas cursus justo vitae purus varius, ut convallis erat imperdiet. Nam elementum viverra metus, sit amet placerat est malesuada vitae. Nullam eget scelerisque elit. Donec vestibulum sapien nec consectetur aliquam. Vivamus cursus mattis mauris, vel laoreet libero. Morbi ullamcorper sed neque id tincidunt. Sed at dui ut risus pellentesque bibendum. Donec accumsan faucibus sem in semper.

Nullam condimentum, nisl ut tincidunt finibus, sem sem imperdiet enim, vitae condimentum justo urna vestibulum diam. Aenean porttitor, orci quis vulputate tristique, augue tellus euismod leo, a interdum odio erat non turpis. Nullam luctus aliquet fermentum. Nunc nisi urna, viverra quis metus non, commodo ullamcorper purus. Pellentesque ut nisl non elit egestas mollis. Vivamus vitae mollis mauris. Nullam sed suscipit massa. Vestibulum libero quam, varius id tortor rutrum, vestibulum consectetur ante. Suspendisse at lectus vel leo aliquet rhoncus. Etiam aliquet, eros et convallis posuere, erat velit pretium diam, a auctor tellus nibh a lacus. Aliquam id justo non ipsum porta aliquet. Donec luctus nulla sed vestibulum tristique. Sed id magna non massa ultricies aliquet. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia curae;

Integer tincidunt lorem in quam interdum dictum. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vivamus sit amet nisl sollicitudin, dapibus urna vitae, efficitur nulla. Donec pharetra massa urna, mattis dignissim ipsum facilisis sit amet. Sed feugiat lectus a lorem placerat, eu euismod felis suscipit. In hac habitasse platea dictumst. Duis convallis nisi at et.`
